// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <endian.h>

#include "timestamping.h"
#include "tstest.h"
#include "liblink.h"

void print_ts(Integer64 ns)
{
	printf("%ld.%ld\n", ns / NS_PER_SEC, ns % NS_PER_SEC);
}

int run_delay_mode(int argc, char **argv)
{
	/*char interface[16] = "veth1";*/
	struct ptp_header hdr;
	union Message message;
	Octet mac[ETH_ALEN];
	char *interface;
	int err;
	unsigned char pkt[1600];
	/*char pkt[14] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00};*/

	if (argc <= 0)
		return EINVAL;

	interface = argv[1];

	str2mac("ff:ff:ff:ff:ff:ff", mac);

	hdr = ptp_header_template();
	ptp_set_type(&hdr, PDELAY_REQ);
	ptp_set_seqId(&hdr, 0x0);
	ptp_set_dmac(&hdr, mac);
	ptp_set_transport_specific(&hdr, 0x0);
	ptp_set_version(&hdr, 2 | (1 << 4));
	ptp_set_domain(&hdr, 0x0);

	if (!interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	message = ptp_msg_create_type(hdr, PDELAY_REQ);
	int len = ptp_msg_get_size(PDELAY_REQ);


	int sock = open_socket(interface, 0, NULL, NULL, 0);
	if (sock < 0)
		return sock;

	struct hw_timestamp hwts = { 0 };
	hwts.type = TS_SOFTWARE;
	err = sk_timestamping_init(sock, interface, hwts.type,
				   TRANS_IEEE_802_3, -1);
	if (err < 0)
		return -err;

	if (argc > 2 && strcmp(argv[2], "client") == 0) {
		err = raw_send(sock, TRANS_EVENT, &message, len, &hwts);
		if (err < 0) {
			return -err;
		}
		return 0;
	}
	/*Integer64 sec = hwts.ts.ns / NS_PER_SEC;*/
	/*Integer64 nsec = hwts.ts.ns % NS_PER_SEC;*/
	/*printf("Timestamp %ld.%ld\n", sec, nsec);*/


	while (1) {
		int err = sk_receive(sock, pkt, 1600, NULL, &hwts, 0);
		if (err < 0) {
			printf("Error. %d\n", err);
			continue;
		}
		/*Integer64 sec = hwts.ts.ns / NS_PER_SEC;*/
		/*Integer64 nsec = hwts.ts.ns % NS_PER_SEC;*/
		/*printf("Timestamp %ld.%ld\n", sec, nsec);*/


		Integer64 req_rx_ts = hwts.ts.ns;
		print_ts(req_rx_ts);
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
		memset(&msg->pdelay_resp.requestReceiptTimestamp, 0, sizeof(struct Timestamp));
		hdr->tsmt = (hdr->tsmt & 0xF0) | PDELAY_RESP;
		/*printf("Type %d\n", msg->pdelay_req.hdr.tsmt & 0xf);*/

		err = raw_send(sock, TRANS_EVENT, msg, ptp_msg_get_size(PDELAY_RESP), &hwts);
		if (err < 0) {
			return -err;
		}

		Integer64 resp_tx_ts = hwts.ts.ns;
		print_ts(resp_tx_ts);

		hdr->tsmt = (hdr->tsmt & 0xF0) | PDELAY_RESP_FUP;
		/*printf("Type %d\n", hdr->tsmt & 0xf);*/
		hdr->correction = htobe64((resp_tx_ts - req_rx_ts) << 16);
		print_ts(resp_tx_ts - req_rx_ts);
		printf("0x%lX\n", resp_tx_ts - req_rx_ts);

		err = raw_send(sock, TRANS_GENERAL, msg, ptp_msg_get_size(PDELAY_RESP_FUP), &hwts);
		if (err < 0) {
			return -err;
		}
		printf("Sent response\n");

	}


	return 0;
}
