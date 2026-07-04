// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>

#include "liblink.h"
#include "pkt.h"
#include "stats.h"
#include "tstest.h"

bool measured_link_delay = true;

void te_help()
{
	fprintf(stderr, "\n--- Time Error Measurement ---\n\n");
	fprintf(stderr,
		"Measure slave side of a TC/BC. Expects a GM to be running on the same PHC.\n\n\
Usage:\n\
        tstest te [options]\n\n\
Options:\n\
        -i <interface>. Port PHC must be synchronized or be the same as GM\n\
        -I <interval ms>. Time between packets. Default 1000 ms\n\
        -D <domain>. PTP domain number\n\
        -c <frame counts>. Default: 10. If 0, send until interrupted\n\
        -d Enable debug output\n\
	-v <2|2.1> PTP version of the packet\n\
        -h help\n\
	--ingressLatency <ns>. Ingress latency of this equipment\n\
	--egressLatency <ns>. Egress latency of this equipment\n\
	--transportSpecific <value>. Set value for the transportSpecific field\n\
        \n\
        Note:\n\
        Negative T1 Time Error indicates positive TX latency\n\
        Positive T4 Time Error indicates positive RX latency\n\
        \n");
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
		resp_fup = build_msg(&port->cfg, PDELAY_RESP_FUP);
		ptp_set_originTimestamp(&resp_fup, tx_ts);
		ptp_set_seqId(&resp_fup.hdr, ptp_get_seqId(&req->hdr));
		ptp_set_requestingPortIdentity(&resp_fup, &req->hdr.sourcePortIdentity);
		send_msg(&port->cfg, port->g_sock, &resp_fup, &tx_ts);
		if (port->do_record)
			record_add_tx_msg(&port->record, &resp_fup, NULL);
	}
	return 0;
}

static void print_offset(Port *port)
{
	int64_t offset;

	offset = port->last_sync_t2t1 - port->current_delay;
	printf("master offset %10" PRId64 " path delay %9" PRId64 "\n", offset,
	       port->current_delay);
}

static int handle_delay(Port *p, int type)
{
	MessageRecord *sync;
	MessageRecord *fup;
	MessageRecord *dreq;
	MessageRecord *dresp;
	MessageRecord *pdreq;
	MessageRecord *pdresp;
	MessageRecord *pdresp_fup;
	int64_t t1;
	int64_t t2;
	int64_t t3;
	int64_t t4;
	int64_t t4ct3;
	int64_t delay;
	uint16_t seqid;

	switch (type) {
	case SYNC:
		sync = port_get_saved(p, SYNC);
		sync->current_delay = p->current_delay;
		sync->current_t4 = p->current_t4;
		if (msg_is_onestep(&sync->msg)) {
			t1 = sync->tx_ts;
			t2 = sync->rx_ts;
			p->last_sync_t2t1 = t2 - t1 - ptp_get_correctionField(&sync->msg);
			DEBUG("T1: %" PRId64 "\n", p->last_sync_t2t1);
			p->sync = -1;
			print_offset(p);
			return 1;
		}
		/* fallthrough */
	case FOLLOW_UP:
		sync = port_get_saved(p, SYNC);
		fup = port_get_saved(p, FOLLOW_UP);
		if (!fup)
			return 0;
		if (sync->seqid != fup->seqid)
			return 0;
		t1 = ptp_get_originTimestamp(&fup->msg);
		t2 = sync->rx_ts;
		p->last_sync_t2t1 = t2 - t1 - ptp_get_correctionField(&sync->msg) -
				    ptp_get_correctionField(&fup->msg);
		/* DEBUG("Sync T1: %" PRId64 "\n", t1); */
		/* DEBUG("Sync T2: %" PRId64 "\n", t2); */
		DEBUG("Sync: %" PRId64 "\n", p->last_sync_t2t1);
		p->sync = -1;
		p->fup = -1;
		print_offset(p);
		return 1;
	case DELAY_RESP:
		dreq = port_get_saved(p, DELAY_REQ);
		dresp = port_get_saved(p, DELAY_RESP);
		if (!dreq || !dresp)
			return 0;
		if (dreq->seqid != dresp->seqid)
			return 0;
		t3 = dreq->tx_ts;
		t4 = ptp_get_originTimestamp(&dresp->msg);
		t4ct3 = t4 - t3 - ptp_get_correctionField(&dresp->msg);
		DEBUG("T4: %" PRId64 "\n", t4ct3);
		// TODO: is this correct?
		p->current_delay = (p->last_sync_t2t1 + t4ct3) / 2;
		p->current_t4 = t4ct3;
		p->dreq = -1;
		p->dresp = -1;
		return 1;
	case PDELAY_RESP:
		pdreq = port_get_saved(p, PDELAY_REQ);
		pdresp = port_get_saved(p, PDELAY_RESP);
		if (!pdreq || !pdresp)
			return 0;
		if (pdreq->seqid != pdresp->seqid)
			return 0;
		if (msg_is_onestep(&pdresp->msg)) {
			t1 = pdreq->tx_ts;
			t4 = pdresp->rx_ts;
			p->current_delay = (t4 - t1 - ptp_get_correctionField(&pdresp->msg)) / 2;
			DEBUG("Pdelay: %" PRId64 "\n", p->current_delay);
			p->pdreq = -1;
			p->pdresp = -1;
			p->pdresp_fup = -1;
		}
		/* fallthrough */
	case PDELAY_RESP_FUP:
		pdreq = port_get_saved(p, PDELAY_REQ);
		pdresp = port_get_saved(p, PDELAY_RESP);
		pdresp_fup = port_get_saved(p, PDELAY_RESP_FUP);
		if (!pdreq || !pdresp || !pdresp_fup)
			return 0;
		if (pdreq->seqid != pdresp->seqid || pdresp->seqid != pdresp_fup->seqid)
			return 0;
		t1 = pdreq->tx_ts;
		t2 = ptp_get_originTimestamp(&pdresp->msg);
		t3 = ptp_get_originTimestamp(&pdresp_fup->msg);
		t4 = pdresp->rx_ts;
		p->current_delay = ((t4 - t1) - (t3 - t2) - ptp_get_correctionField(&pdresp->msg) -
				    ptp_get_correctionField(&pdresp_fup->msg)) /
				   2;
		pdreq->current_delay = p->current_delay;
		DEBUG("Pdelay: %" PRId64 "\n", p->current_delay);
		p->pdreq = -1;
		p->pdresp = -1;
		p->pdresp_fup = -1;
		return 1;
	default:
		return 0;
	}
	return 0;
}

int te_event(Port *port, int fd_index)
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
		case SYNC:
			port_save_last_added(port);
			handle_delay(port, SYNC);
			break;
		case DELAY_REQ:
			ERR("Unexpected DELAY_REQ received\n");
			break;
		case PDELAY_REQ:
			pdelay_resp(port, &msg, ns);
			break;
		case PDELAY_RESP:
			port_save_last_added(port);
			handle_delay(port, PDELAY_RESP);
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
		switch (msg_get_type(&msg)) {
		case FOLLOW_UP:
			port_save_last_added(port);
			handle_delay(port, FOLLOW_UP);
			break;
		case DELAY_RESP:
			port_save_last_added(port);
			handle_delay(port, DELAY_RESP);
			break;
		case PDELAY_RESP_FUP:
			port_save_last_added(port);
			handle_delay(port, PDELAY_RESP_FUP);
			break;
		default:
			break;
		}
		break;
	case FD_DELAY_TIMER:
		read(port->pollfd[fd_index].fd, dummybuf, 8);
		if (port->cfg.dm == DM_E2E) {
			send_pkt(port, DELAY_REQ);
			port_save_last_added(port);
			port->dresp = -1;
		} else {
			send_pkt(port, PDELAY_REQ);
			port_save_last_added(port);
			port->pdresp = -1;
			port->pdresp_fup = -1;
		}

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
	case FD_ANNOUNCE_TIMER:
		break;
	case FD_SYNC_TX_TIMER:
		break;
	default:
		read(port->pollfd[fd_index].fd, dummybuf, 8);
		ERR("Unhandled event on FD index %d\n", fd_index);
		break;
	}

out:
	return err;
}

/* TODO: BC needs to know what the current delay/pdelay was when receiving a Sync */
static void run(Port *p)
{
	Stats s;
	int err;

	p->delay_req_count = p->cfg.count;

	port_set_timer(p, FD_DELAY_TIMER, p->cfg.interval);
	/* port_set_timer(p2, FD_SYNC_TX_TIMER, p->cfg.interval); */
	/* port_set_timer(p2, FD_ANNOUNCE_TIMER, 1000); */

	while (is_running() && p->delay_req_count > 0) {
		port_poll(p);
	}

	/* Do a couple extra polls to pick up any remaining messages */
	for (int i = 0; i < 100; i++) {
		port_poll(p);
	}

	err = stats_init(&s, p->cfg.dm);
	if (err)
		return;
	stats_collect_port_record(&p->record, &s);
	stats_show_te(&s, p->cfg.interface, 0, measured_link_delay);
	/* stats_show(&s, p1->cfg.interface, p2->cfg.interface, p1->sync_count + p2->delay_req_count); */
	/* stats_output_measurements(&s, "measurements.dat"); */
	stats_free(&s);
}

static int te_parse_opt(int argc, char **argv, struct pkt_cfg *cfg, char **p1)
{
	int type;
	int c;

	str2mac("01:1b:19:00:00:00", cfg->mac);
	cfg->tstype = TS_HARDWARE;
	cfg->version = 2; // | (1 << 4);
	cfg->twoStepFlag = 1;
	cfg->count = 10;
	cfg->interval = 1000;
	cfg->listen = -1;
	cfg->dm = DM_E2E;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 { "ingressLatency", required_argument, NULL, 2 },
					 { "egressLatency", required_argument, NULL, 3 },
					 /* { "twoStepFlag", required_argument, NULL, 2 }, */
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		te_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "EPSdD:hI:i:m:c:v:oO", long_options, NULL)) != -1) {
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
		case 'O':
			cfg->tstype = TS_P2P1STEP;
			break;
		case 'i':
			if (*p1 == NULL) {
				*p1 = optarg;
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
			te_help();
			return EINVAL;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EINVAL;
		default:
			te_help();
			return EINVAL;
		}
	}

	if (!p1) {
		printf("Must specify port. Use -i ethN\n");
		return EINVAL;
	}

	return 0;
}

int run_te_mode(int argc, char **argv)
{
	enum transport_event event_type;
	struct pkt_cfg cfg = { 0 };
	int p1_sock, p2_sock;
	char *p = NULL;
	int count;
	int err;

	err = te_parse_opt(argc, argv, &cfg, &p);
	if (err)
		return err;

	/* signal(SIGINT, sig_handler); */
	handle_term_signals();

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	Port port;
	port_init(&port, cfg, p, te_event, true, true, true);

	count = cfg.count;
	run(&port);

out:
	port_free(&port);
	return 0;
}
