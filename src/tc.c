// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include "liblink.h"
#include "pkt.h"
#include "stats.h"

/* Measure the one-way inaccuracy through a TC. Runs on two ports that
 * are either synchronized or use the same PHC. The inaccuracies will
 * be the cable delay + any uncompensated rx/tx latencies.
 *
 * The host should set --ingressLatency and --egressLatency. If the rx/tx
 * latencies aren't exactly known they can be set to the same value as
 * they will cancel each other out.
 *
 * The value can be found by measuring the inaccuracy (minus the cable
 * delay) and dividing by 2, with a looped cable. This is the same
 * process as measuring the peer delay.
 *
 * ingressLatency = egressLatency = peer_delay - cable_delay
 *
 * Wiretime (https://github.com/cappe987/wiretime) could also be used
 * for this purpose if adapted to handle correction time and
 * ingress/egress latency.
 */

/* TODO:
 * - Support twostep mode? To test offloaded 2-step TC
 * - Add support to reply to pdelay messages for P2P TC?
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

void tc_help()
{
	fprintf(stderr, "\n--- TSTest Transparent Clock ---\n\n");
	fprintf(stderr,
		"Sends packets through a TC, back to the same device to measure TC compensation\n\n\
Usage:\n\
        tstest tc [options]\n\n\
Options:\n\
        -i <interface>. Must be used twice. Port PHCs must be synchronized or be the same\n\
        -I <interval ms>. Time between packets. Default 200 ms\n\
        -D <domain>. PTP domain number\n\
        -c <frame counts>. Default: 10. If 0, send until interrupted\n\
        -b Bidirectional. Run measurements in both directions\n\
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

static int receive(struct pkt_cfg *cfg, int p2_sock, PortRecord *pr)
{
	struct hw_timestamp hwts;
	unsigned char buf[1600];
	union Message *rx_msg;
	int cnt;

	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	rx_msg = (union Message *)buf;

	do {
		cnt = sk_receive(p2_sock, rx_msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
		/* TODO: Handle receiving other packet types here
		 * (e.g. pdelays). We only want to consider Syncs
		 * Handle onestep syncs.
		 */
		if (cnt < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		record_add_rx_msg(pr, rx_msg, &hwts.ts.ns);
		/* seqid = be16toh(rx_msg->hdr.sequenceId); */
		/* rx_ts = hwts.ts.ns; */
		/* correction = be64toh(rx_msg->hdr.correction) >> 16; */
		return 0;
	} while (tc_running);

	return 1;
}

static void send_pkt(struct pkt_cfg *cfg, int sock, PortRecord *pr)
{
	struct hw_timestamp hwts;
	union Message msg;
	;
	int64_t tx_ts;
	int type;
	int i;

	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	for (i = 0; i < cfg->sequence_length; i++) {
		type = cfg->sequence_types[i];
		msg = build_msg(cfg, type);
		send_msg(cfg, sock, &msg, &tx_ts);
		record_add_tx_msg(pr, &msg, &tx_ts);
		/* build_and_send(cfg, sock, type, &hwts, tx_ts); */
		cfg->seq++;
		/* Default: 100 ms */
		usleep(cfg->interval * 1000);
	}
}

static void run(struct pkt_cfg *cfg, char *p1, char *p2, int p1_sock, int p2_sock)
{
	int64_t rx_ts, tx_ts, correction, total_err;
	struct hw_timestamp hwts;
	struct timeval timeout;
	PortRecord pr_tx;
	PortRecord pr_rx;
	uint16_t seqid;
	Stats s;
	int err;
	int i;

	record_init(&pr_tx, p1, 100);
	record_init(&pr_rx, p2, 100);
	err = stats_init(&s, cfg->count);
	if (err)
		return;

	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	/* XXX: When swapping the ports, does this affect the TX timestamp???
	 * Maybe if longer tx_timestamp_timeout is required.
	 */
	if (setsockopt(p2_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
		ERR("setsockopt failed: %m\n");

	while (cfg->count || cfg->nonstop_flag) {
		rx_ts = 0;
		tx_ts = 0;
		correction = 0;

		send_pkt(cfg, p1_sock, &pr_tx);
		err = receive(cfg, p2_sock, &pr_rx);
		if (err || !tc_running) {
			printf("Stopping!\n");
			break;
		}

		/* With a proper TC, only the cable delay should be left uncompensated for */
		/* Total delay accrued (RX - TX - RESIDENCE - SELF.INGR_LAT - SELF.EGR_LAT) */
		/* tx_ts += cfg->egressLatency; */
		/* rx_ts -= cfg->ingressLatency; */
		/* total_err = rx_ts - tx_ts - correction; */
		/* DEBUG("%s -> %s. TX: %" PRId64 ". RX: %" PRId64 ". Corr: %" PRId64 */
		/*       ". Result: %" PRId64 "\n", */
		/*       p1, p2, tx_ts, rx_ts, correction, total_err); */
		if (!debugen) {
			printf(".");
			fflush(stdout);
		}
		if (cfg->count > 0)
			cfg->count--;
	}

	if (!debugen && tc_running)
		printf("\n");
	record_map_messages(&s, &pr_tx, &pr_rx);
	stats_show(&s, p1, p2, cfg->count);
	stats_output_measurements(&s, "measurements.dat");
	stats_free(&s);
	record_free(&pr_tx);
	record_free(&pr_rx);
}

static int tc_parse_opt(int argc, char **argv, struct pkt_cfg *cfg, char **p1, char **p2,
			int *bidirectional)
{
	int type;
	int c;

	str2mac("01:1b:19:00:00:00", cfg->mac);
	cfg->tstype = TS_HARDWARE;
	cfg->version = 2; // | (1 << 4);
	cfg->twoStepFlag = 1;
	cfg->count = 10;
	cfg->interval = 100;
	cfg->listen = -1;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 { "ingressLatency", required_argument, NULL, 2 },
					 { "egressLatency", required_argument, NULL, 3 },
					 /* { "twoStepFlag", required_argument, NULL, 2 }, */
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		tc_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "SdD:hI:i:m:c:v:b", long_options, NULL)) != -1) {
		switch (c) {
		case 1:
			cfg->transportSpecific = strtoul(optarg, NULL, 0);
			break;
		case 2:
			cfg->ingressLatency = strtoul(optarg, NULL, 0);
			break;
		case 3:
			cfg->egressLatency = strtoul(optarg, NULL, 0);
			break;
		case 'S':
			cfg->tstype = TS_SOFTWARE;
			break;
		case 'i':
			if (*p1 == NULL) {
				*p1 = optarg;
			} else if (*p2 == NULL) {
				*p2 = optarg;
			} else {
				printf("Too many ports\n");
				return EINVAL;
			}
			break;
		case 'I':
			cfg->interval = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			cfg->count = strtoul(optarg, NULL, 0);
			break;
		/* case 'f': */
		/* 	cfg->auto_fup = 1; */
		/* 	break; */
		case 'm':
			if (str2mac(optarg, cfg->mac)) {
				printf("error mac input\n");
				return EINVAL;
			}
			break;
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
		case 'b':
			*bidirectional = 1;
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

	if (!p1 || !p2) {
		printf("Needs two ports. Use -i ethN -i ethM to specify two ports\n");
		return EINVAL;
	}

	return 0;
}

int run_tc_mode(int argc, char **argv)
{
	enum transport_event event_type;
	struct pkt_cfg cfg = { 0 };
	int p1_sock, p2_sock;
	char *p1 = NULL, *p2 = NULL;
	int bidirectional = 0;
	int count;
	int err;

	err = tc_parse_opt(argc, argv, &cfg, &p1, &p2, &bidirectional);
	if (err)
		return err;

	signal(SIGINT, sig_handler);

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	p1_sock = open_socket(p1, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (p1_sock < 0) {
		ERR_NO("failed to open socket");
		return p1_sock;
	}

	err = sk_timestamping_init(p1_sock, p1, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK, cfg.tstype,
				   TRANS_IEEE_802_3, -1, 0, DM_E2E, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	p2_sock = open_socket(p2, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (p2_sock < 0) {
		ERR_NO("failed to open socket");
		return p2_sock;
	}

	err = sk_timestamping_init(p2_sock, p2, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK, cfg.tstype,
				   TRANS_IEEE_802_3, -1, 0, DM_E2E, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	count = cfg.count;
	run(&cfg, p1, p2, p1_sock, p2_sock);
	if (!bidirectional)
		goto out;
	if (!tc_running)
		goto out;

	/* TODO: Should we recreate the sockets when swapping direction? */
	printf("Swapping direction...\n");
	cfg.count = count;
	run(&cfg, p2, p1, p2_sock, p1_sock);

out:
	sk_timestamping_destroy(p1_sock, p1, cfg.tstype);
	sk_timestamping_destroy(p2_sock, p2, cfg.tstype);
	return 0;
}
