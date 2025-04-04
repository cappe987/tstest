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
#include "tstest.h"

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
        -d Enable debug output\n\
	-v <2|2.1> PTP version of the packet\n\
        -h help\n\
	--ingressLatency <ns>. Ingress latency of this equipment\n\
	--egressLatency <ns>. Egress latency of this equipment\n\
	--transportSpecific <value>. Set value for the transportSpecific field\n\
        \n");
}

/* static int receive(struct pkt_cfg *cfg, int p2_sock, PortRecord *pr) */
/* { */
/* 	struct hw_timestamp hwts; */
/* 	unsigned char buf[1600]; */
/* 	union Message *rx_msg; */
/* 	int cnt; */

/* 	hwts.type = cfg->tstype; */
/* 	hwts.ts.ns = 0; */

/* 	rx_msg = (union Message *)buf; */

/* 	do { */
/* 		cnt = sk_receive(p2_sock, rx_msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT); */
/* 		/\* TODO: Handle receiving other packet types here */
/* 		 * (e.g. pdelays). We only want to consider Syncs */
/* 		 * Handle onestep syncs. */
/* 		 *\/ */
/* 		if (cnt < 0 && (errno == EAGAIN || errno == EINTR)) */
/* 			continue; */
/* 		if (hwts.ts.ns > 0) */
/* 			hwts.ts.ns -= cfg->ingressLatency; */
/* 		record_add_rx_msg(pr, rx_msg, &hwts.ts.ns); */
/* 		return 0; */
/* 	} while (is_running()); */

/* 	return 1; */
/* } */

static void send_pkt_with_ts(Port *port, int ptp_type, int64_t ts, int64_t correction)
{
	struct hw_timestamp hwts;
	union Message msg;
	int64_t tx_ts;
	int i = 0;

	hwts.type = port->cfg.tstype;
	hwts.ts.ns = 0;

	msg = build_msg_with_ts(&port->cfg, ptp_type, 0, 0);
	send_msg(&port->cfg, port_get_socket(port, ptp_type), &msg, &tx_ts);
	if (tx_ts > 0)
		tx_ts += port->cfg.egressLatency;
	if (port->do_record)
		record_add_tx_msg(&port->record, &msg, &tx_ts);
	if (ptp_type == SYNC && port->cfg.tstype != TS_ONESTEP && port->cfg.tstype != TS_P2P1STEP) {
		msg = build_msg(&port->cfg, FOLLOW_UP);
		ptp_set_originTimestamp(&msg, tx_ts);
		send_msg(&port->cfg, port->g_sock, &msg, &tx_ts);
		if (port->do_record)
			record_add_tx_msg(&port->record, &msg, NULL);
	}
	port->cfg.seq++;
}

static void send_pkt(Port *port, int ptp_type)
{
	send_pkt_with_ts(port, ptp_type, 0, 0);
}

static int delay_resp(Port *port, union Message *req, int64_t ns)
{
	int64_t correction = ptp_get_correctionField(req);
	struct hw_timestamp hwts;
	union Message resp;
	int64_t tx_ts;
	int i = 0;

	hwts.type = port->cfg.tstype;
	hwts.ts.ns = 0;

	resp = build_msg_with_ts(&port->cfg, DELAY_RESP, ns, correction);
	ptp_set_seqId(&resp.hdr, ptp_get_seqId(&req->hdr));
	ptp_set_requestingPortIdentity(&resp, &req->hdr.sourcePortIdentity);
	send_msg(&port->cfg, port->g_sock, &resp, &tx_ts);
	if (port->do_record)
		record_add_tx_msg(&port->record, &resp, NULL);
	return 0;
}

static int pdelay_resp(Port *port, union Message *req, int64_t ns)
{
	int64_t correction = ptp_get_correctionField(req);
	struct hw_timestamp hwts;
	union Message resp;
	union Message resp_fup;
	int64_t tx_ts;
	int i = 0;

	hwts.type = port->cfg.tstype;
	hwts.ts.ns = 0;

	resp = build_msg_with_ts(&port->cfg, PDELAY_RESP, ns, correction);
	ptp_set_seqId(&resp.hdr, ptp_get_seqId(&req->hdr));
	ptp_set_requestingPortIdentity(&resp, &req->hdr.sourcePortIdentity);
	send_msg(&port->cfg, port->e_sock, &resp, &tx_ts);
	if (port->do_record)
		record_add_tx_msg(&port->record, &resp, NULL);
	if (port->cfg.tstype != TS_P2P1STEP) {
		resp_fup = build_msg(&port->cfg, FOLLOW_UP);
		ptp_set_originTimestamp(&resp_fup, tx_ts);
		ptp_set_seqId(&resp_fup.hdr, ptp_get_seqId(&req->hdr));
		ptp_set_requestingPortIdentity(&resp_fup, &req->hdr.sourcePortIdentity);
		send_msg(&port->cfg, port->g_sock, &resp_fup, &tx_ts);
		if (port->do_record)
			record_add_tx_msg(&port->record, &resp_fup, NULL);
	}
	return 0;
}

int tc_event(Port *port, int fd_index)
{
	struct hw_timestamp hwts = { 0 };
	unsigned char dummybuf[8];
	union Message msg;
	int64_t ns;
	int err = 0;

	hwts.type = port->cfg.tstype;

	if (fd_index < 0) {
		ERR("Invalid FD index %d\n", fd_index);
		return -EINVAL;
	}

	switch (fd_index) {
	case FD_EVENT:
		err = sk_receive(port->e_sock, &msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
		if (err < 0)
			goto out;
		ns = hwts.ts.ns - port->cfg.ingressLatency;
		if (port->do_record)
			record_add_rx_msg(&port->record, &msg, &ns);
		switch (msg_get_type(&msg)) {
		case DELAY_REQ:
			delay_resp(port, &msg, ns);
			break;
		case PDELAY_REQ:
			pdelay_resp(port, &msg, ns);
			break;
		default:
			break;
		}
		break;
	case FD_GENERAL:
		err = sk_receive(port->g_sock, &msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
		if (err < 0)
			goto out;
		if (port->do_record)
			record_add_rx_msg(&port->record, &msg, NULL);
		break;
	case FD_SYNC_TX_TIMER:
		read(port->pollfd[fd_index].fd, dummybuf, 8);
		send_pkt(port, SYNC);
		/* if (!port->cfg.nonstop_flag) */
		/* port->cfg.count--; */
		/* if (!debugen) { */
		/* 	printf("."); */
		/* 	fflush(stdout); */
		/* } */
		port->sync_count--;
		if (port->sync_count == 0 && !port->cfg.nonstop_flag) {
			err = -EINTR;
			port_clear_timer(port, FD_SYNC_TX_TIMER);
		}
		break;
	case FD_DELAY_TIMER:
		read(port->pollfd[fd_index].fd, dummybuf, 8);
		if (port->cfg.dm == DM_E2E)
			send_pkt(port, DELAY_REQ);
		else
			send_pkt(port, PDELAY_REQ);
		/* if (!port->cfg.nonstop_flag) */
		/* port->cfg.count--; */
		/* if (!debugen) { */
		/* 	printf("."); */
		/* 	fflush(stdout); */
		/* } */
		port->delay_req_count--;
		if (port->delay_req_count == 0 && !port->cfg.nonstop_flag) {
			err = -EINTR;
			port_clear_timer(port, FD_DELAY_TIMER);
		}
		break;
	default:
		read(port->pollfd[fd_index].fd, dummybuf, 8);
		ERR("Unhandled event on FD index %d\n", fd_index);
		break;
	}

out:
	return err;
}

static void run(Port *p1, Port *p2)
{
	Stats s;
	int err;

	p1->sync_count = p1->cfg.count;
	p2->delay_req_count = p2->cfg.count;

	port_set_timer(p1, FD_SYNC_TX_TIMER, p1->cfg.interval);
	port_set_timer(p2, FD_DELAY_TIMER, p2->cfg.interval);

	while (is_running() && p1->sync_count > 0 && p2->delay_req_count > 0) {
		port_poll(p1);
		port_poll(p2);
	}

	/* Both sides get a couple extra polls to pick up any remaining messages */
	for (int i = 0; i < 100; i++) {
		port_poll(p1);
		port_poll(p2);
	}

	err = stats_init(&s, p1->cfg.dm);
	if (err)
		return;
	stats_collect_port_record(&p2->record, &s);
	stats_show(&s, p1->cfg.interface, p2->cfg.interface, p1->sync_count + p2->delay_req_count);
	stats_output_measurements(&s, "measurements.dat");
	stats_free(&s);
}

static int tc_parse_opt(int argc, char **argv, struct pkt_cfg *cfg, char **p1, char **p2)
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
	cfg->dm = DM_E2E;

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

	while ((c = getopt_long(argc, argv, "EPSdD:hI:i:m:c:v:o", long_options, NULL)) != -1) {
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
		case 'E':
			cfg->dm = DM_E2E;
			break;
		case 'P':
			cfg->dm = DM_P2P;
			break;
		case 'S':
			cfg->tstype = TS_SOFTWARE;
			break;
		case 'o':
			cfg->tstype = TS_ONESTEP;
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
	int count;
	int err;

	err = tc_parse_opt(argc, argv, &cfg, &p1, &p2);
	if (err)
		return err;

	/* signal(SIGINT, sig_handler); */
	handle_term_signals();

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	Port port1;
	Port port2;
	/* port_init(&port1, cfg, p1, tc_event, true, true, true); */
	port_init(&port1, cfg, p1, tc_event, false, true, true);
	port_init(&port2, cfg, p2, tc_event, true, true, true);

	count = cfg.count;
	run(&port1, &port2);

out:
	port_free(&port1);
	port_free(&port2);
	return 0;
}
