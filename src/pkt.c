// SPDX-License-Identifier: GPL-2.0-only SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include "net_tstamp_cpy.h"

#include "timestamping.h"
#include "liblink.h"
#include "tstest.h"

/* TODO:
 * - Fix tstamp-all
 *
 */

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

extern int debugen;

struct pkt_cfg {
	int so_timestamping_flags;
	int transportSpecific;
	int twoStepFlag_set;
	int onestep_listen;
	int nonstop_flag;
	int twoStepFlag;
	int tstamp_all;
	int auto_fup;
	int ptp_type;
	int onestep;
	int rx_only;
	int version;
	int domain;
	int tstype;
	int count;
	int prio;
	int seq;
	char mac[ETH_ALEN];
	char *interface;
};

void pkt_help()
{
	fprintf(stderr, "\n--- TSTest Packets ---\n\n");
	fprintf(stderr, "Transmits and receives PTP packets and outputs the timestamps.\n\n\
Usage:\n\
        tstest pkt [options]\n\n\
Options:\n\
        -i <interface> \n\
        -T <PTP type> \n\
        -t TX only mode \n\
        -r RX only mode \n\
        -a Timestamp all packets (CURRENTLY NOT WORKING) \n\
        -D Domain \n\
        -o Use one-step timestamping \n\
        -O Use p2p-one-step timestamping \n\
        -s <sequence id> \n\
        -m <destination MAC> \n\
        -c <frame counts> \n\
        -p <priority> \n\
        -d Enable debug output\n\
        -h help\n\
        \n");
}

int send_auto_fup(struct pkt_cfg *cfg, int sock)
{
	struct ptp_header hdr;
	union Message msg;
	int ptp_type;
	int err;

	if (cfg->ptp_type == SYNC)
		ptp_type = FOLLOW_UP;
	else if (cfg->ptp_type == PDELAY_RESP)
		ptp_type = PDELAY_RESP_FUP;
	else
		return -EINVAL;

	hdr = ptp_header_template();
	ptp_set_type(&hdr, ptp_type);
	ptp_set_seqId(&hdr, cfg->seq);
	ptp_set_dmac(&hdr, cfg->mac);
	ptp_set_transport_specific(&hdr, cfg->transportSpecific);
	ptp_set_version(&hdr, cfg->version);
	ptp_set_domain(&hdr, cfg->domain);
	ptp_set_flags(&hdr, 0);

	msg = ptp_msg_create_type(hdr, ptp_type);
	return raw_send(sock, TRANS_GENERAL, &msg, ptp_msg_get_size(ptp_type), NULL);
}

int pkt_parse_opt(int argc, char **argv, struct pkt_cfg *cfg)
{
	int c;

	str2mac("ff:ff:ff:ff:ff:ff", cfg->mac);
	cfg->tstype = TS_HARDWARE;
	cfg->version = 2 | (1 << 4);
	cfg->twoStepFlag = 1;
	cfg->count = 1;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 { "twoStepFlag", required_argument, NULL, 2 },
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		pkt_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "StrapdfDl:hoOi:m:c:s:T:v:", long_options, NULL)) !=
	       -1) {
		switch (c) {
		case 1:
			cfg->transportSpecific = strtoul(optarg, NULL, 0);
			break;
		case 2:
			cfg->twoStepFlag = strtoul(optarg, NULL, 0);
			cfg->twoStepFlag_set = 1;
			break;
		case 'T':
			cfg->ptp_type = str2ptp_type(optarg);
			if (cfg->ptp_type < 0) {
				printf("Invalid ptp type\n");
				return -1;
			}
			break;
		case 'S':
			cfg->tstype = TS_SOFTWARE;
			break;
		case 'a':
			cfg->tstamp_all = 1;
			break;
		case 'o':
			cfg->onestep = 1;
			cfg->tstype = TS_ONESTEP;
			break;
		case 'O':
			cfg->onestep = 1;
			cfg->tstype = TS_P2P1STEP;
			break;
		case 'l':
			cfg->tstype = TS_ONESTEP;
			cfg->onestep_listen = 1;
			cfg->onestep = 1;
			break;
		case 's':
			cfg->seq = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			cfg->interface = optarg;
			break;
		case 'r':
			cfg->rx_only = 1;
			break;
		case 'm':
			if (str2mac(optarg, cfg->mac)) {
				printf("error mac input\n");
				return EINVAL;
			}
			break;
		case 'c':
			cfg->count = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			cfg->prio = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			cfg->auto_fup = 1;
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
		case 'h':
			pkt_help();
			return EINVAL;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EINVAL;
		default:
			pkt_help();
			return EINVAL;
		}
	}

	return 0;
}

int run_pkt_mode(int argc, char **argv)
{
	enum transport_event event_type;
	struct pkt_cfg cfg = { 0 };
	struct hw_timestamp hwts;
	unsigned char buf[1600];
	struct ptp_header hdr;
	union Message tx_msg;
	union Message *rx_msg;
	int sock;
	int err;

	err = pkt_parse_opt(argc, argv, &cfg);

	hdr = ptp_header_template();
	ptp_set_type(&hdr, cfg.ptp_type);
	ptp_set_seqId(&hdr, cfg.seq);
	ptp_set_dmac(&hdr, cfg.mac);
	ptp_set_transport_specific(&hdr, cfg.transportSpecific);
	ptp_set_version(&hdr, cfg.version);
	ptp_set_domain(&hdr, cfg.domain);

	if (!cfg.interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	if (cfg.auto_fup && (cfg.ptp_type != SYNC && cfg.ptp_type != PDELAY_RESP)) {
		fprintf(stderr,
			"Error: auto-follow-up can only be used with sync and pdelay_resp\n");
		return EINVAL;
	}

	if (cfg.twoStepFlag_set) {
		if (cfg.twoStepFlag)
			ptp_set_flags(&hdr, 0x02);
		else
			ptp_set_flags(&hdr, 0x00);
	} else {
		/* Auto-clear twoStepFlag when one-step sync is set.
		 * Later this also needs to handle p2p1step.
		 */
		if (cfg.onestep && cfg.ptp_type == SYNC || cfg.tstype == TS_P2P1STEP && cfg.ptp_type == PDELAY_RESP)
			ptp_set_flags(&hdr, 0);
	}

	tx_msg = ptp_msg_create_type(hdr, cfg.ptp_type);

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	/* Using this new method the tstamp_all will not work. Will
	 * pdelay_req/resp work correctly with one-step/p2p1step?
	 */

	rx_msg = (union Message *)buf;

	hwts.type = cfg.tstype;
	hwts.ts.ns = 0;
	sock = open_socket(cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (sock < 0) {
		ERR_NO("failed to open socket");
		return sock;
	}

	err = sk_timestamping_init(sock, cfg.interface, cfg.tstype, TRANS_IEEE_802_3, -1);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	if (cfg.rx_only) {
		while (1) {
			sk_receive(sock, rx_msg, 1600, NULL, &hwts, 0);
			printf("Type: %s. ", ptp_type2str(rx_msg->hdr.tsmt & 0xF));
			print_ts("TS: ", hwts.ts.ns);
		}
	}

	if (cfg.onestep && !cfg.onestep_listen)
		event_type = cfg.tstype == TS_P2P1STEP ? TRANS_P2P1STEP : TRANS_ONESTEP;
	else if (cfg.ptp_type & 0x8)
		event_type = TRANS_GENERAL;
	else
		event_type = TRANS_EVENT;

	while (cfg.count || cfg.nonstop_flag) {
		err = raw_send(sock, event_type, &tx_msg, ptp_msg_get_size(cfg.ptp_type), &hwts);
		print_ts("TS: ", hwts.ts.ns);
		if (!cfg.nonstop_flag)
			cfg.count--;
		if (cfg.auto_fup) {
			/* Allow the sync to send first to avoid out-of-order */
			usleep(50000);
			send_auto_fup(&cfg, sock);
		}
	}

	return 0;
}
