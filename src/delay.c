// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <endian.h>
#include <unistd.h>

#include "timestamping.h"
#include "tstest.h"
#include "liblink.h"

/* TODO:
 * - Create function calculate_pdelay that takes
 *   t1,t2,t3,t4,resp_corr,resp_fup_corr and calculates based on what mode
 *   delay modes is set.
 * - Implement mmedian_sample delay filter (ptp4l delay_filter)
 * - Implement one-step P2P
 * - Implement E2E
 * - Set twoStepFlag correctly
 */

struct delay_cfg {
	enum delay_mechanism delay;
	enum timestamp_type tstype;
	UInteger8 domain;
	Integer8 version;
	Integer64 count;
	char *interface;
};

void delay_help()
{
	fprintf(stderr, "\n--- TSTest Delay ---\n\n");
	fprintf(stderr, "Measures PTP path delay\n\n\
Usage:\n\
        tstest delay <server|client> [options]\n\n\
Options:\n\
        -i <interface> \n\
        -o Use one-step P2P \n\
        -E Use E2E delay \n\
        -c <frame counts>. Client only, performs N measurements\n\
        -D Set domain number\n\
        -v Set PTP version number\n\
        -d Enable debug output\n\
        -h help\n\
        --delay_filter <moving_median|moving_average>. Default: moving_median.\n\
        \n");
}

void print_ts(char *text, Integer64 ns)
{
	printf("%s: %ld.%ld\n", text, ns / NS_PER_SEC, ns % NS_PER_SEC);
}

void increment_seq(struct ptp_header *hdr)
{
	hdr->sequenceId = htons(ntohs(hdr->sequenceId) + 1);
}

int msg_get_type(union Message *msg)
{
	return msg->hdr.tsmt & 0xF;
}

int receive_packet(int e_sock, int g_sock, struct timeval *tv, int expected_type,
		   union Message *msg, Integer64 *ns)
{
	int nfds = e_sock > g_sock ? e_sock + 1 : g_sock + 1;
	struct hw_timestamp hwts = { 0 };
	fd_set fds;
	int type;
	int res;
	int err;

	FD_ZERO(&fds);
	FD_SET(e_sock, &fds);
	FD_SET(g_sock, &fds);

	while (1) {
		res = select(nfds, &fds, 0, NULL, tv);
		if (res < 0) {
			return -errno;
		}
		if (res == 0) {
			ERR("timed out waiting for %s", ptp_type2str(expected_type));
			return -ETIMEDOUT;
		}

		if (FD_ISSET(e_sock, &fds)) {
			err = sk_receive(e_sock, msg, 1600, NULL, &hwts, 0);
			if (err < 0) {
				return err;
			}
			type = msg_get_type(msg);
			if (!(type == expected_type)) {
				WARN("event: received wrong PTP type. Expected %s. Got %s",
				     ptp_type2str(expected_type), ptp_type2str(type));
				continue;
			}

			*ns = hwts.ts.ns;
			return 0;
		} else if (FD_ISSET(g_sock, &fds)) {
			err = sk_receive(g_sock, msg, 1600, NULL, &hwts, 0);
			if (err < 0) {
				return err;
			}
			type = msg_get_type(msg);
			if (!(type == expected_type)) {
				WARN("general: received wrong PTP type. Expected %s. Got %s",
				     ptp_type2str(expected_type), ptp_type2str(type));
				continue;
			}
			return 0;
		}
	}
}

int run_delay_client(int e_sock, int g_sock, struct delay_cfg *cfg)
{
	Integer64 pdelay, pdelay_resp_corr, pdelay_resp_fup_corr;
	struct hw_timestamp hwts = { 0 };
	struct timeval tv = { 0, 100000 };
	Integer64 t1, t2, t3, t4;
	unsigned char buf[1600];
	struct ptp_header hdr;
	union Message *recv;
	union Message req;
	Octet mac[ETH_ALEN];
	UInteger16 seq = 0;
	int err;
	int len;

	hwts.type = cfg->tstype;
	str2mac(p2p_dst_mac, mac);

	hdr = ptp_header_template();
	ptp_set_type(&hdr, PDELAY_REQ);
	ptp_set_dmac(&hdr, mac);
	ptp_set_transport_specific(&hdr, 0x0);
	ptp_set_version(&hdr, cfg->version);
	ptp_set_domain(&hdr, cfg->domain);

	req = ptp_msg_create_type(hdr, PDELAY_REQ);
	len = ptp_msg_get_size(PDELAY_REQ);

	recv = (union Message *)buf;

	while (cfg->count != 0) {
		ptp_set_seqId(&req.hdr, seq);
		err = raw_send(e_sock, TRANS_EVENT, &req, len, &hwts);
		if (err < 0) {
			return -err;
		}
		t1 = hwts.ts.ns;

		err = receive_packet(e_sock, g_sock, &tv, PDELAY_RESP, recv, &t4);
		if (err < 0) {
			return -err;
		}
		if (ptp_get_seqId(&recv->hdr) != seq) {
			ERR("pdelay_resp: wrong seqId. Expected %d. Got %d", seq,
			    ptp_get_seqId(&recv->hdr));
			return EINVAL;
		}
		t2 = be_timestamp_to_ns(recv->pdelay_resp.requestReceiptTimestamp);
		pdelay_resp_corr = be64toh(recv->hdr.correction) >> 16;

		err = receive_packet(e_sock, g_sock, &tv, PDELAY_RESP_FUP, recv, NULL);
		if (err < 0) {
			return -err;
		}
		if (ptp_get_seqId(&recv->hdr) != seq) {
			ERR("pdelay_resp_fup: wrong seqId. Expected %d. Got %d", seq,
			    ptp_get_seqId(&recv->hdr));
			return EINVAL;
		}

		t3 = be_timestamp_to_ns(recv->pdelay_resp_fup.responseOriginTimestamp);
		pdelay_resp_fup_corr = be64toh(recv->hdr.correction) >> 16;
		pdelay = ((t4 - t1) - (t3 - t2) - pdelay_resp_corr - pdelay_resp_fup_corr) / 2;
		printf("Pdelay %ld\n", pdelay);

		seq++;
		cfg->count--;
		if (cfg->count != 0)
			usleep(1000000);
	}
	return 0;
}

int run_delay_server(int e_sock, int g_sock, struct delay_cfg *cfg)
{
	Integer64 corrField, req_rx_ts, resp_tx_ts;
	struct hw_timestamp hwts = { 0 };
	unsigned char buf[1600];
	struct Timestamp ts;
	union Message *recv;
	Integer64 sec, nsec;
	int err;

	hwts.type = cfg->tstype;

	recv = (union Message *)buf;

	while (1) {
		err = receive_packet(e_sock, g_sock, NULL, PDELAY_REQ, recv, &req_rx_ts);
		if (err < 0) {
			return -err;
		}

		/* Two-step peer delay response. IEEE1588-2019, 11.4.2 (c) */
		corrField = recv->hdr.correction; // Use for resp-fup
		recv->hdr.correction = 0; // Reset for resp
		memcpy(&recv->pdelay_resp.requestingPortIdentity, &recv->hdr.sourcePortIdentity,
		       sizeof(struct PortIdentity));
		// TODO: Set our own sourcePortIdentity
		// TODO: Set twoStepFlag when doing two-step response
		memcpy(&recv->hdr.sourcePortIdentity.clockIdentity.id,
		       "\xaa\xaa\xaa\xff\xfe\xaa\xaa\xaa", 6);

		recv->pdelay_resp.requestReceiptTimestamp = ns_to_be_timestamp(req_rx_ts);
		ptp_set_type(&recv->hdr, PDELAY_RESP);

		err = raw_send(e_sock, TRANS_EVENT, recv, ptp_msg_get_size(PDELAY_RESP), &hwts);
		if (err < 0) {
			return -err;
		}

		resp_tx_ts = hwts.ts.ns;
		ptp_set_type(&recv->hdr, PDELAY_RESP_FUP);
		recv->hdr.correction = corrField;
		recv->pdelay_resp_fup.responseOriginTimestamp = ns_to_be_timestamp(resp_tx_ts);
		err = raw_send(g_sock, TRANS_GENERAL, recv, ptp_msg_get_size(PDELAY_RESP_FUP),
			       NULL);
		if (err < 0) {
			return -err;
		}
	}
}

int delay_parse_opt(int argc, char **argv, struct delay_cfg *cfg)
{
	int c;

	cfg->version = 2 | (1 << 4);
	cfg->delay = DM_P2P;
	cfg->tstype = TS_HARDWARE;
	cfg->domain = 0;
	cfg->count = -1;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 /*{ "transportSpecific", required_argument, NULL, 1 },*/
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		delay_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "ESohi:c:D:v:", long_options, NULL)) != -1) {
		switch (c) {
		case 'E':
			cfg->delay = DM_E2E;
			break;
		case 'S':
			cfg->tstype = TS_SOFTWARE;
			break;
		case 'o':
			cfg->tstype = TS_P2P1STEP;
			break;
		case 'i':
			cfg->interface = optarg;
			break;
		case 'c':
			cfg->count = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			cfg->domain = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			if (optarg == NULL)
				printf("bad version input\n");
			else if (strncmp(optarg, "2.1", 3) == 0)
				cfg->version = 2 | (1 << 4);
			else if (strncmp(optarg, "2", 1) == 0)
				cfg->version = 2;
			else
				printf("bad version input\n");
			break;
		/*case 'd':*/
			/*debugen = 1;*/
			/*break;*/
		case 'h':
			delay_help();
			return 1;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			delay_help();
			return 1;
		}
	}

	if (!cfg->interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	return 0;
}

int run_delay_mode(int argc, char **argv)
{
	struct delay_cfg cfg = { 0 };
	int err, e_sock, g_sock;
	int client_mode;

	if (argc <= 1) {
		delay_help();
		return EINVAL;
	}

	if (strcmp(argv[1], "client") == 0) {
		client_mode = 1;
	} else if (strcmp(argv[1], "server") == 0) {
		client_mode = 0;
	} else {
		ERR("expected 'client' or 'server' mode");
		return EINVAL;
	}
	argc--;
	argv = &argv[1];

	delay_parse_opt(argc, argv, &cfg);

	e_sock = open_socket(cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0);
	if (e_sock < 0)
		return e_sock;
	g_sock = open_socket(cfg.interface, 0, ptp_dst_mac, p2p_dst_mac, 0);
	if (g_sock < 0)
		return g_sock;

	err = sk_timestamping_init(e_sock, cfg.interface, cfg.tstype, TRANS_IEEE_802_3, -1);
	if (err < 0)
		return -err;

	if (client_mode) {
		return run_delay_client(e_sock, g_sock, &cfg);
	} else {
		return run_delay_server(e_sock, g_sock, &cfg);
	}

	return 0;
}
