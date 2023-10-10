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
 * - Clean up and separate server and client
 * - Arguments for domain, version, etc.
 * - Implement mmedian_sample delay filter (ptp4l delay_filter)
 * - Implement one-step P2P
 * - Implement E2E
 */

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

int run_delay_client(int e_sock, int g_sock, enum timestamp_type type)
{
	struct hw_timestamp hwts = { 0 };
	unsigned char pkt[1600];
	struct ptp_header hdr;
	union Message message;
	Octet mac[ETH_ALEN];
	int err;
	int len;

	hwts.type = type;
	str2mac("ff:ff:ff:ff:ff:ff", mac);

	hdr = ptp_header_template();
	ptp_set_type(&hdr, PDELAY_REQ);
	ptp_set_seqId(&hdr, 0x0);
	ptp_set_dmac(&hdr, mac);
	ptp_set_transport_specific(&hdr, 0x0);
	ptp_set_version(&hdr, 2 | (1 << 4));
	ptp_set_domain(&hdr, 0x0);

	message = ptp_msg_create_type(hdr, PDELAY_REQ);
	len = ptp_msg_get_size(PDELAY_REQ);

	while (1) {
		err = raw_send(e_sock, TRANS_EVENT, &message, len, &hwts);
		if (err < 0) {
			return -err;
		}
		Integer64 t1 = hwts.ts.ns;
		message.pdelay_req.hdr.sequenceId = htons(ntohs(message.pdelay_req.hdr.sequenceId)+1);
		err = sk_receive(e_sock, pkt, 1600, NULL, &hwts, 0);
		if (err < 0) {
			return -err;
		}
		struct ptp_header *hdr = (struct ptp_header*) pkt;
		union Message *msg = (union Message*) pkt;
		Integer64 t2 = be_timestamp_to_ns(msg->pdelay_resp.requestReceiptTimestamp);
		Integer64 t4 = hwts.ts.ns;
		Integer64 pdelay_resp_corr = be64toh(hdr->correction) >> 16;

		err = sk_receive(g_sock, pkt, 1600, NULL, &hwts, 0);
		if (err < 0) {
			return -err;
		}
		hdr = (struct ptp_header*) pkt;
		/*printf("Type %d\n", hdr->tsmt & 0xf);*/

		Integer64 t3 = be_timestamp_to_ns(msg->pdelay_resp_fup.responseOriginTimestamp);
		Integer64 pdelay_resp_fup_corr = be64toh(hdr->correction) >> 16;
		Integer64 pdelay = ((t4 - t1) - (t3 - t2) - pdelay_resp_corr - pdelay_resp_fup_corr)/2;
		printf("Pdelay %ld\n", pdelay);

		usleep(1000000);
	}
	return 0;
}

int run_delay_server(int e_sock, int g_sock, enum timestamp_type type)
{
	struct hw_timestamp hwts = { 0 };
	unsigned char pkt[1600];
	int err;

	hwts.type = type;

	while (1) {
		err = sk_receive(e_sock, pkt, 1600, NULL, &hwts, 0);
		if (err < 0) {
			printf("Error. %d\n", err);
			continue;
		}

		Integer64 req_rx_ts = hwts.ts.ns;
		/*print_ts("req", req_rx_ts);*/
		struct ptp_header *hdr = (struct ptp_header*) pkt;
		union Message *msg = (union Message*) pkt;
		int type = hdr->tsmt & 0xF;
		/*printf("Type %d\n", hdr->tsmt & 0xf);*/

		if (type != PDELAY_REQ)
			continue;

		/* Two-step peer delay response. 1588, 11.4.2 (c) */
		Integer64 corrField = hdr->correction; // Use for resp-fup
		hdr->correction = 0; // Reset for resp
		memcpy(&msg->pdelay_resp.requestingPortIdentity,
		       &hdr->sourcePortIdentity,
		       sizeof(struct PortIdentity));
		// TODO: Set our own sourcePortIdentity
		memcpy(&hdr->sourcePortIdentity.clockIdentity.id, "\xaa\xaa\xaa\xff\xfe\xaa\xaa\xaa", 6);
		struct Timestamp ts;
		Integer64 sec = req_rx_ts / NS_PER_SEC;
		Integer32 nsec = req_rx_ts % NS_PER_SEC;
		ts.seconds_lsb = sec & 0xFFFFFFFF;
		ts.seconds_msb = (sec >> 32) & 0xFFFF;
		ts.nanoseconds = nsec;

		msg->pdelay_resp.requestReceiptTimestamp = ns_to_be_timestamp(req_rx_ts);
		hdr->tsmt = (hdr->tsmt & 0xF0) | PDELAY_RESP;

		err = raw_send(e_sock, TRANS_EVENT, msg, ptp_msg_get_size(PDELAY_RESP), &hwts);
		if (err < 0) {
			return -err;
		}

		Integer64 resp_tx_ts = hwts.ts.ns;
		/*print_ts("resp", resp_tx_ts);*/

		hdr->tsmt = (hdr->tsmt & 0xF0) | PDELAY_RESP_FUP;
		msg->pdelay_resp_fup.responseOriginTimestamp = ns_to_be_timestamp(resp_tx_ts);
		/*hdr->correction = htobe64((resp_tx_ts - req_rx_ts) << 16);*/
		/*print_ts("diff", resp_tx_ts - req_rx_ts);*/

		err = raw_send(g_sock, TRANS_GENERAL, msg, ptp_msg_get_size(PDELAY_RESP_FUP), NULL);
		if (err < 0) {
			return -err;
		}
		/*printf("Sent response\n");*/
	}

}

int run_delay_mode(int argc, char **argv)
{
	enum timestamp_type type;
	int err, e_sock, g_sock;
	int client_mode;
	char *interface;

	type = TS_SOFTWARE;

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

	// FIXME: Do proper argument parsing
	if (argc > 3 && strcmp(argv[2], "-i") == 0) {
		interface = argv[3];
	}

	if (!interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	e_sock = open_socket(interface, 1, ptp_dst_mac, p2p_dst_mac, 0);
	if (e_sock < 0)
		return e_sock;
	g_sock = open_socket(interface, 0, ptp_dst_mac, p2p_dst_mac, 0);
	if (g_sock < 0)
		return g_sock;

	err = sk_timestamping_init(e_sock, interface, type,
				   TRANS_IEEE_802_3, -1);
	if (err < 0)
		return -err;

	if (client_mode) {
		return run_delay_client(e_sock, g_sock, type);
	} else {
		return run_delay_server(e_sock, g_sock, type);
	}

	return 0;
}
