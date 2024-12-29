
// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2024 Casper Andersson <casper.casan@gmail.com>

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <inttypes.h>

#include "net_tstamp_cpy.h"

#include "timestamping.h"
#include "liblink.h"
#include "tstest.h"
#include "pkt.h"

/* TODO:
 * - Fix tstamp-all
 */

int tc_running = 1;

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
#define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
#define SIOCSHWTSTAMP 0x89b0
#endif

struct thread_cfg {
	struct pkt_cfg *cfg;
	struct hw_timestamp hwts;
	int sock;
};

void tc_help()
{
	fprintf(stderr, "\n--- TSTest Transparent Clock ---\n\n");
	fprintf(stderr, "Sends packets through a TC, back to the same device to measure TC compensation\n\n\
Usage:\n\
        tstest tc [options]\n\n\
Options:\n\
        -i <interface>\n\
        -I <interval ms>. Time between packets. Default 200 ms\n\
        -D <domain>. PTP domain number\n\
        -c <frame counts>. If not set, send until interrupted\n\
        -d Enable debug output\n\
	-v <2|2.1> PTP version of the packet\n\
        -h help\n\
	--ingressLatency <ns>. Ingress latency of this equipment\n\
	--egressLatency <ns>. Egress latency of this equipment\n\
	--transportSpecific <value>. Set value for the transportSpecific field\n\
        \n");
}

static void sig_handler(int sig)
{
	tc_running = 0;
}

static void set_two_step_flag(struct pkt_cfg *cfg, struct ptp_header *hdr, int type)
{
	int twoStepFlag = 0x00;

	if (cfg->twoStepFlag_set) {
		// Manually control two-step flag
		if (cfg->twoStepFlag)
			twoStepFlag = 0x02;
		else
			twoStepFlag = 0x00;
	} else {
		if (type == SYNC && cfg->tstype != TS_ONESTEP && cfg->tstype != TS_P2P1STEP)
			twoStepFlag = 0x02;
		else if (type == PDELAY_RESP && cfg->tstype != TS_P2P1STEP)
			twoStepFlag = 0x02;
	}

	ptp_set_flags(hdr, twoStepFlag);
}

static int get_event_type(struct pkt_cfg *cfg, int type)
{
	if (cfg->listen == 1) // Force listen
		return TRANS_EVENT;
	if (cfg->listen == 0) // Force quiet
		return TRANS_GENERAL;

	if (type == PDELAY_REQ)
		return TRANS_EVENT; // Always timestamp pdelay_req
	else if (cfg->tstype == TS_P2P1STEP && type == PDELAY_RESP)
		return TRANS_GENERAL; // Don't timestamp pdelay_resp on p2p1step
	else if ((cfg->tstype == TS_ONESTEP || cfg->tstype == TS_P2P1STEP) && type == SYNC)
		return TRANS_GENERAL; // Don't timestamp sync on onestep and p2p1step
	else if (type & 0x8)
		return TRANS_GENERAL; // Don't timestamp general packets
	else
		return TRANS_EVENT; // Timestamp rest
}

/* static int send_print(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts) */
/* { */
/* 	enum transport_event event_type; */
/* 	int64_t ns; */
/* 	int err; */

/* 	err = build_and_send(cfg, sock, type, hwts, &ns); */
/* 	print_ts("TS: ", ns); */
/* 	return err; */
/* } */

/* static int send_auto_fup(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts) */
/* { */
/* 	struct ptp_header hdr; */
/* 	union Message msg; */
/* 	int ptp_type; */
/* 	int err; */

/* 	if (type == SYNC) */
/* 		type = FOLLOW_UP; */
/* 	else if (type == PDELAY_RESP) */
/* 		type = PDELAY_RESP_FUP; */
/* 	else */
/* 		return -EINVAL; */

/* 	return send_print(cfg, sock, ptp_type, hwts); */
/* } */

static void tx_mode(struct pkt_cfg *cfg, int sock, struct hw_timestamp *hwts)
{
	int64_t ns;
	int type;
	int i;

	while (cfg->count || cfg->nonstop_flag) {
		for (i = 0; i < cfg->sequence_length; i++) {
			type = cfg->sequence_types[i];
			build_and_send(cfg, sock, type, hwts, &ns);
			cfg->seq++;
			/* Default: 200 ms */
			usleep(cfg->interval * 1000);
		}
		// Not working (?? old comment?)
		if (!cfg->nonstop_flag)
			cfg->count--;
	}

	sk_timestamping_destroy(sock, cfg->interface, cfg->tstype);
}

static int64_t timestamp_to_ns(struct Timestamp ts)
{
	int64_t ns;

	ns = ((int64_t)ts.seconds_msb << 32) * NS_PER_SEC;
	ns += (int64_t)ts.seconds_lsb * NS_PER_SEC;
	ns += ts.nanoseconds;
	return ns;
}

static void *rx_mode(void *args)
{
	struct thread_cfg *tcfg = (struct thread_cfg *) args;
	struct hw_timestamp hwts = tcfg->hwts;
	struct pkt_cfg *cfg = tcfg->cfg;
	int64_t tx_ts, rx_ts, correction, result;
	unsigned char buf[1600];
	struct timeval timeout;
	union Message *rx_msg;
	int sock = tcfg->sock;
	int cnt;

	rx_msg = (union Message *)buf;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
		ERR("setsockopt failed: %m\n");

	while (tc_running) {
		cnt = sk_receive(sock, rx_msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
		if (cnt < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		printf("Type: %s. ", ptp_type2str(rx_msg->hdr.tsmt & 0xF));
		tx_ts = timestamp_to_ns(rx_msg->sync.originTimestamp);
		rx_ts = hwts.ts.ns;
		correction = be64toh(rx_msg->hdr.correction);

		result = rx_ts - tx_ts - correction - cfg->ingressLatency - cfg->egressLatency;
		/* With a proper TC, only the cable delay should be left uncompensated for */
		printf("Total uncompensated time %"PRId64"\n", result);
		/* print_ts("TS: ", hwts->ts.ns); */
		// Total delay accrued (RX - TX - RESIDENCE - SELF.INGR_LAT - SELF.EGR_LAT)
	}

	sk_timestamping_destroy(sock, cfg->interface, cfg->tstype);
	return NULL;
}

static int pkt_parse_opt(int argc, char **argv, struct pkt_cfg *cfg)
{
	int type;
	int c;

	str2mac("01:1b:19:00:00:00", cfg->mac);
	cfg->tstype = TS_ONESTEP;
	cfg->version = 2; // | (1 << 4);
	cfg->twoStepFlag = 0;
	cfg->count = 0;
	cfg->interval = 200;
	/* cfg->listen = -1; */

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 /* { "twoStepFlag", required_argument, NULL, 2 }, */
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		tc_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "StrapdfD:l:hoOI:i:m:c:s:T:v:", long_options, NULL)) !=
	       -1) {
		switch (c) {
		case 1:
			cfg->transportSpecific = strtoul(optarg, NULL, 0);
			break;
		/* case 2: */
		/* 	cfg->twoStepFlag = strtoul(optarg, NULL, 0); */
		/* 	cfg->twoStepFlag_set = 1; */
		/* 	break; */
		case 'T':
			if (cfg->sequence_length >= SEQUENCE_MAX) {
				printf("Sequence too long. Max %d\n", SEQUENCE_MAX);
				return -1;
			}

			type = str2ptp_type(optarg);
			if (type < 0) {
				printf("Invalid ptp type\n");
				printf("Expected: sync|follow_up|delay_req|delay_resp|pdelay_req|pdelay_resp|pdelay_resp_fup|announce|management|signaling\n");
				return -1;
			}
			cfg->sequence_types[cfg->sequence_length] = type;
			cfg->sequence_length++;
			break;
		/* case 'S': */
		/* 	cfg->tstype = TS_SOFTWARE; */
		/* 	break; */
		/* case 'a': */
		/* 	cfg->tstamp_all = 1; */
		/* 	break; */
		/* case 'o': */
		/* 	cfg->tstype = TS_ONESTEP; */
		/* 	break; */
		/* case 'O': */
		/* 	cfg->tstype = TS_P2P1STEP; */
		/* 	break; */
		/* case 'l': */
		/* 	// Force listen or not listen to TS */
		/* 	cfg->listen = strtol(optarg, NULL, 0); */
		/* 	break; */
		/* case 's': */
		/* 	cfg->seq = strtoul(optarg, NULL, 0); */
		/* 	break; */
		case 'i':
			cfg->interface = optarg;
			break;
		case 'I':
			cfg->interval = strtoul(optarg, NULL, 0);
			break;
		/* case 'r': */
		/* 	cfg->rx_only = 1; */
		/* 	break; */
		/* case 'm': */
		/* 	if (str2mac(optarg, cfg->mac)) { */
		/* 		printf("error mac input\n"); */
		/* 		return EINVAL; */
		/* 	} */
		/* 	break; */
		case 'c':
			cfg->count = strtoul(optarg, NULL, 0);
			break;
		/* case 'f': */
		/* 	cfg->auto_fup = 1; */
		/* 	break; */
		case 'D':
			cfg->domain = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			if (optarg == NULL) {
				printf("bad version input\n");
			} else if (strncmp(optarg, "2.1", 3) == 0) {
				cfg->version = 2 | (1 << 4);
			} else if (strncmp(optarg, "2", 1) == 0) {
				cfg->version = 2;
			} else {
				printf("bad version input\n");
				return EINVAL;
			}
			break;
		case 'd':
			debugen = 1;
			break;
		case 'h':
			tc_help();
			return EINVAL;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EINVAL;
		default:
			tc_help();
			return EINVAL;
		}
	}

	if (cfg->sequence_length == 0) {
		cfg->sequence_types[0] = SYNC;
		cfg->sequence_length = 1;
	}

	return 0;
}

int run_tc_mode(int argc, char **argv)
{
	enum transport_event event_type;
	struct pkt_cfg cfg = { 0 };
	struct hw_timestamp hwts;
	int tx_sock, rx_sock;
	int err;

	err = pkt_parse_opt(argc, argv, &cfg);
	if (err)
		return err;

	if (!cfg.interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	signal(SIGINT, sig_handler);

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	hwts.type = cfg.tstype;
	hwts.ts.ns = 0;
	tx_sock = open_socket(cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (tx_sock < 0) {
		ERR_NO("failed to open socket");
		return tx_sock;
	}

	err = sk_timestamping_init(tx_sock, cfg.interface, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK,
				   cfg.tstype, TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	rx_sock = open_socket(cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (tx_sock < 0) {
		ERR_NO("failed to open socket");
		return rx_sock;
	}

	err = sk_timestamping_init(rx_sock, cfg.interface, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK,
				   cfg.tstype, TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	struct thread_cfg tcfg;
	pthread_t rx_thread;
	tcfg.sock = rx_sock;
	tcfg.hwts = hwts;
	tcfg.cfg = &cfg;
	/* rx_mode(&cfg, rx_sock, &hwts); */
	pthread_create(&rx_thread, NULL, rx_mode, &tcfg);
	usleep(1000);
	tx_mode(&cfg, tx_sock, &hwts);
	sk_timestamping_destroy(rx_sock, cfg.interface, cfg.tstype);

	return 0;
}
