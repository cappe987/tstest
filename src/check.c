// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "net_tstamp_cpy.h"

#include "timestamping.h"
#include "liblink.h"
#include "tstest.h"
#include "pkt.h"

#define TEST_PASS 0
#define TEST_FAIL -1

int send_and_receive(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, union Message **rx_msg) {
	struct hw_timestamp hwts;
	int tx_bytes, rx_bytes;
	int64_t ns;
	int err;

	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	tx_bytes = build_and_send(cfg, txsock, ptp_type, &hwts, &ns);
	if (tx_bytes < 0) // Convert to positive errno
		return -tx_bytes;
	rx_bytes = sk_receive(rxsock, rx_msg, 1600, NULL, &hwts, 0);
	if (rx_bytes < 0) // Convert to positive errno
		return -rx_bytes;

	if (tx_bytes != rx_bytes) {
		printf("Different amount of bytes tx/rx: %d/%d\n", tx_bytes, rx_bytes);
		return TEST_FAIL;
	}

	return TEST_PASS;
}

int send_and_check(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts, int expect_rx_ts) {
	struct hw_timestamp hwts;
	unsigned char buf[1600];
	int tx_bytes, rx_bytes;
	union Message *rx_msg;
	int result_tx = 0;
	int result_rx = 0;
	int64_t ns;

	rx_msg = (union Message *)buf;
	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	tx_bytes = build_and_send(cfg, txsock, ptp_type, &hwts, &ns);

	/*print_ts("TX TS: ", ns);*/

	rx_bytes = sk_receive(rxsock, rx_msg, 1600, NULL, &hwts, 0);
	/*print_ts("RX TS: ", hwts.ts.ns);*/

	/*tx_bytes = send_and_receive(cfg, txsock, rxsock, ptp_type, &rx_msg, &rx_bytes);*/

	if (tx_bytes != rx_bytes) {
		printf("Different amount of bytes tx/rx: %d/%d\n", tx_bytes, rx_bytes);
	}

	if (expect_tx_ts && ns == 0) {
		printf("TX failed. Expected timestamp\n");
		result_tx = TEST_FAIL;
	} else if (!expect_tx_ts && ns > 0) {
		printf("TX failed. Got timestamp\n");
		result_tx = TEST_FAIL;
	}

	if (expect_rx_ts && hwts.ts.ns == 0) {
		printf("RX failed. Expected timestamp\n");
		result_rx = TEST_FAIL;
	} else if (!expect_rx_ts && hwts.ts.ns > 0) {
		printf("RX failed. Got timestamp\n");
		result_rx = TEST_FAIL;
	}

	/*printf("TX %d. RX %d\n", tx_bytes, rx_bytes);*/
	/*print_ts("TS: ", hwts.ts.ns);*/

	return result_tx || result_rx;
}

int check_type(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts, int expect_rx_ts) {
	int err;

	err = send_and_check(cfg, txsock, rxsock, ptp_type, expect_tx_ts, expect_rx_ts);
	if (err) {
		printf("Failed %s\n", ptp_type2str(ptp_type));
		return TEST_FAIL;
	}

	return TEST_PASS;
}

int setup_sockets(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface, int *txsock, int *rxsock) {
	int err;

	// XXX: Filters disables so we can run events and non-events on same socket
	*txsock = open_socket(tx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 0);
	if (*txsock < 0) {
		ERR_NO("failed to open socket");
		return errno;
	}

	err = sk_timestamping_init(*txsock, tx_iface, cfg->tstype, TRANS_IEEE_802_3, -1);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return errno;
	}

	// XXX: Filters disables so we can run events and non-events on same socket
	*rxsock = open_socket(rx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 0);
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

void teardown_sockets(int txsock, int rxsock) {
	close(txsock);
	close(rxsock);
}

void print_result(char *str, int result) {
	if (result == TEST_PASS)
		printf("- \e[32m[Passed]\e[0m %s\n", str);
	else if (result == TEST_FAIL)
		printf("- \e[31m[Failed]\e[0m %s\n", str);
	else
		printf("- \e[31m[Error]\e[0m %s\n", str);
}

int check_onestep_ts(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	struct hw_timestamp hwts;
	unsigned char buf[1600];
	int result = TEST_PASS;
	union Message *rx_msg;
	struct Timestamp ts;
	int txsock, rxsock;
	int64_t ns;
	int err;

	cfg->tstype = TS_ONESTEP;
	
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;
		

	result = send_and_receive(cfg, txsock, rxsock, SYNC, &rx_msg);
	if (result)
		goto out;

	ts = rx_msg->sync.originTimestamp;
	if (ts.seconds_msb == 0 && ts.seconds_lsb == 0 && ts.nanoseconds == 0) {
		printf("Expected onestep timestamp in received packet\n");
		result = TEST_FAIL;
		goto out;
	}

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_p2p1step_ts(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	cfg->tstype = TS_P2P1STEP;
	
	// TODO: Check correctionField? Potentially it could work with originTimestamp
}

int check_software_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_SOFTWARE;
 
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, SYNC,            1, 1);
	result |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);
	result |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       1, 1);
	result |= check_type(cfg, txsock, rxsock, DELAY_RESP,      1, 1);
	result |= check_type(cfg, txsock, rxsock, ANNOUNCE,        1, 1);
	result |= check_type(cfg, txsock, rxsock, SIGNALING,       1, 1);
	result |= check_type(cfg, txsock, rxsock, MANAGEMENT,      1, 1);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 1, 1);

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_hardware_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_HARDWARE;
 
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, SYNC,            1, 1);
	result |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);
	result |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	result |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	result |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	result |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	result |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_onestep_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_ONESTEP;
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, SYNC,            0, 1);
	result |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);
	result |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	result |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	result |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	result |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	result |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_p2p1step_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface) {
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_P2P1STEP;
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, SYNC,            0, 1);
	/*result |= check_type(cfg, txsock, rxsock, DELAY_REQ,       1, 1);*/
	result |= check_type(cfg, txsock, rxsock, FOLLOW_UP,       0, 0);
	result |= check_type(cfg, txsock, rxsock, DELAY_RESP,      0, 0);
	result |= check_type(cfg, txsock, rxsock, ANNOUNCE,        0, 0);
	result |= check_type(cfg, txsock, rxsock, SIGNALING,       0, 0);
	result |= check_type(cfg, txsock, rxsock, MANAGEMENT,      0, 0);

	str2mac("01:80:c2:00:00:0E", cfg->mac);
	result |= check_type(cfg, txsock, rxsock, PDELAY_REQ,      1, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP,     0, 1);
	result |= check_type(cfg, txsock, rxsock, PDELAY_RESP_FUP, 0, 0);

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

// TODO: Implement argument handling
int run_check_mode(int argc, char **argv) {
	int timestamping_mode = TS_HARDWARE;
	struct pkt_cfg cfg = { 0 };
	char *tx_iface = "veth1";
	char *rx_iface = "veth2";
	int do_all = 0;
	int result = TEST_PASS;

	cfg.transportSpecific = 0;
	cfg.version = 2 | (1 << 4);
	cfg.domain = 0;
	cfg.seq = 0;
	cfg.listen = 1;

	timestamping_mode = TS_SOFTWARE;

	switch (timestamping_mode) {
	case TS_SOFTWARE:
		printf("\e[34m[Software timestamping]\e[0m\n");
		result = check_software_timestamp(&cfg, tx_iface, tx_iface);
		print_result("Timestamping", result);
		if (!do_all)
			break;
	case TS_HARDWARE:
		printf("\e[34m[Hardware timestamping]\e[0m\n");
		result = check_hardware_timestamp(&cfg, tx_iface, tx_iface);
		print_result("Timestamping", result);
		if (!do_all)
			break;
	case TS_ONESTEP:
		printf("\e[34m[Onestep timestamping]\e[0m\n");
		result = check_hardware_timestamp(&cfg, tx_iface, tx_iface);
		print_result("Timestamping", result);

		result = check_onestep_ts(&cfg, tx_iface, tx_iface);
		print_result("Onestep Sync", result);
		if (!do_all)
			break;
	case TS_P2P1STEP:
		printf("\e[34m[Peer-to-peer onestep timestamping]\e[0m\n");
		result = check_hardware_timestamp(&cfg, tx_iface, tx_iface);
		print_result("Timestamping", result);

		result = check_onestep_ts(&cfg, tx_iface, tx_iface);
		print_result("Onestep Sync", result);

		result = check_p2p1step_ts(&cfg, tx_iface, tx_iface);
		print_result("Onestep Peer delay", result);
		if (!do_all)
			break;
	default:
		break;
	}
	return result;
}



