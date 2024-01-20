// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <errno.h>

#include "net_tstamp_cpy.h"

#include "timestamping.h"
#include "liblink.h"
#include "tstest.h"
#include "pkt.h"


int send_and_check(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts, int expect_rx_ts) {
	struct hw_timestamp hwts;
	unsigned char buf[1600];
	int tx_bytes, rx_bytes;
	union Message *rx_msg;
	int err_tx = 0;
	int err_rx = 0;
	int64_t ns;

	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	tx_bytes = build_and_send(cfg, txsock, SYNC, &hwts, &ns);

	/*print_ts("TX TS: ", ns);*/

	rx_msg = (union Message *)buf;
	rx_bytes = sk_receive(rxsock, rx_msg, 1600, NULL, &hwts, 0);
	/*print_ts("RX TS: ", hwts.ts.ns);*/

	if (tx_bytes != rx_bytes) {
		printf("Different amount of bytes tx/rx: %d/%d\n", tx_bytes, rx_bytes);
		/*return -1;*/
	}

	if (expect_tx_ts && ns == 0) {
		printf("TX failed. Expected timestamp\n");
		err_tx = -1;
	} else if (!expect_tx_ts && ns > 0) {
		printf("TX failed. Got timestamp\n");
		err_tx = -1;
	}

	if (expect_rx_ts && hwts.ts.ns == 0) {
		printf("RX failed. Expected timestamp\n");
		err_rx = -1;
	} else if (!expect_rx_ts && hwts.ts.ns > 0) {
		printf("RX failed. Got timestamp\n");
		err_rx = -1;
	}

	/*printf("TX %d. RX %d\n", tx_bytes, rx_bytes);*/
	/*print_ts("TS: ", hwts.ts.ns);*/

	return err_tx || err_rx;
}

int check_type(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts, int expect_rx_ts) {
	int err;

	err = send_and_check(cfg, txsock, rxsock, ptp_type, expect_tx_ts, expect_rx_ts);
	if (err) {
		printf("Failed %s\n", ptp_type2str(ptp_type));
		return -1;
	}

	return 0;
}

int setup_sockets(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface, int *txsock, int *rxsock) {
	int err;

	*txsock = open_socket(tx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (*txsock < 0) {
		ERR_NO("failed to open socket");
		return errno;
	}

	err = sk_timestamping_init(*txsock, tx_iface, cfg->tstype, TRANS_IEEE_802_3, -1);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return errno;
	}

	*rxsock = open_socket(rx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (*rxsock < 0) {
		ERR_NO("failed to open socket");
		return errno;
	}

	err = sk_timestamping_init(*rxsock, tx_iface, cfg->tstype, TRANS_IEEE_802_3, -1);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return errno;
	}

	return 0;
}

void print_result(int result) {
	if (result)
		printf("\e[31m[Failed]\e[0m\n");
	else
		printf("\e[32m[Passed]\e[0m\n");
}

int check_software_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int txsock, rxsock;
	int64_t ns;
	int err;

	cfg->tstype = TS_SOFTWARE;
 
	err = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (err)
		return err;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, SYNC,        1, 1);
	err |= check_type(cfg, txsock, rxsock, DELAY_REQ,   1, 1);
	err |= check_type(cfg, txsock, rxsock, FOLLOW_UP,   1, 1);
	err |= check_type(cfg, txsock, rxsock, DELAY_RESP,  1, 1);
	err |= check_type(cfg, txsock, rxsock, ANNOUNCE,    1, 1);
	err |= check_type(cfg, txsock, rxsock, SIGNALING,   1, 1);
	err |= check_type(cfg, txsock, rxsock, MANAGEMENT,  1, 1);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, PDELAY_REQ,  1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP, 1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 1, 1);

	print_result(err);
	return err;
}

int check_hardware_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int txsock, rxsock;
	int64_t ns;
	int err;

	cfg->tstype = TS_HARDWARE;
 
	err = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (err)
		return err;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, SYNC,            1, 1);
	err |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);
	err |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	err |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	err |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	err |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	err |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

	print_result(err);
	return err;
}

int check_onestep_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int txsock, rxsock;
	int64_t ns;
	int err;

	cfg->tstype = TS_ONESTEP;
 
	err = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (err)
		return err;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, SYNC,            0, 1);
	err |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);
	err |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	err |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	err |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	err |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	err |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

	print_result(err);
	return err;
}

int check_p2p1step_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int txsock, rxsock;
	int64_t ns;
	int err;

	cfg->tstype = TS_P2P1STEP;
	err = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (err)
		return err;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, SYNC,            0, 1);
	/*err |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);*/
	err |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	err |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	err |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	err |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	err |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	err |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     0, 1);
	err |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

	print_result(err);
	return err;
}

int run_check_mode(int argc, char **argv) {

	struct pkt_cfg cfg = { 0 };

	cfg.transportSpecific = 0;
	cfg.version = 2 | (1 << 4);
	cfg.domain = 0;
	cfg.seq = 0;
	cfg.listen = 1;

	return check_software_timestamp(&cfg, "veth1", "veth2");
}



