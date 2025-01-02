// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "liblink.h"
#include "pkt.h"

/* #define TEST_PASS 0 */
/* #define TEST_FAIL -1 */

#define TSTEST_CHECK_DOMAIN 123
#define TSTEST_CHECK_SEQ_NR 5000
#define TSTEST_CHECK_VLAN_PRIO 4

typedef enum { TEST_PASS, TEST_FAIL, TEST_INVALID } Result;

/* Test cases to implement:
 * OC/BC mode:
 * - TX Sync Twostep    (expect TX timestamp)
 * - TX Sync Onestep    (expect originTS set on RX port)
 * - TX Sync P2p1step   (expect originTS set on RX port)
 * - RX Sync Twostep    (expect RX timestamp from sync)
 * - RX Sync Onestep    (expect RX timestamp from sync)
 * - RX Sync P2p1step   (expect RX timestamp from sync)
 *
 * P2P:
 * - TX Pdelay_req Twostep  (expect TX timestamp)
 * - TX Pdelay_req Onestep  (expect TX timestamp)
 * - TX Pdelay_req P2p1step (expect TX timestamp)
 * - RX Pdelay_req Twostep  (expect RX timestamp)
 * - RX Pdelay_req Onestep  (expect RX timestamp)
 * - RX Pdelay_req P2p1step (expect RX timestamp)
 *
 * - TX Pdelay_resp Twostep  (expect TX timestamp) Except if pdelay_dummy_resp_fup
 * - TX Pdelay_resp Onestep  (expect TX timestamp) Except if pdelay_dummy_resp_fup
 * - TX Pdelay_resp P2p1step (expect TX timestamp) Except if pdelay_dummy_resp_fup
 * - RX Pdelay_resp Twostep  (expect RX timestamp)
 * - RX Pdelay_resp Onestep  (expect RX timestamp)
 * - RX Pdelay_resp P2p1step (expect RX timestamp)
 *
 * E2E (retest Sync for both P2P and E2E):
 * - TX Delay_req Twostep  (expect TX timestamp)
 * - TX Delay_req Onestep  (expect TX timestamp)
 * - RX Delay_req Twostep  (expect RX timestamp)
 * - RX Delay_req Onestep  (expect RX timestamp)
 *
 *
 *
 * TC mode:
 * - Most of BC mode ???
 * E2E:
 * - TX Sync Onestep TC (expect correctionField to be modified, depends on reserved2)
 *
 * P2P:
 * - TX Sync Onestep  (expect correctionField to be modified, depends on reserved2)
 * - TX Sync P2p1step (expect correctionField to be modified, depends on reserved2)
 * - RX Sync Onestep  (expect reserved2 to be set)
 * - RX Sync P2p1step (expect reserved2 to be set)
 *
 *
 *
 * VLAN tagging
 * - Untagged
 * - Tagged VID 0
 * - Tagged VID 100
 *
 * Check TS capabilities before trying Software/Twostep/Onestep/P2p1step
 *
 *
 * Timestamp performance testing:
 * - TX timestamp: spam twostep sync for ~2 seconds. Compare all
     timestamps and see how many were within a second.
 * - RX timestamp: Setup TX for onestep. Use originTS as definition
     for a second. See how many RX we were able to get. Gradually
     increase/decrease TX delay until we manage to RX timestamp all.
 *
 *
 * Each test function should have the following type signature:
 * Result testcase(char *tx_port, char *rx_port);
 * The idea is that each test sets up everything it needs.
 *
 *
 * Port monitor mode (listen to traffic on a port that runs PTP).
 * Could be separate from `tstest check`. Maybe `tstest monitor`?
 * Can snoop traffic and regularly query daemon and report status to
 * remove server. Could be run on several devices and have server
 * aggregate the data. Write server in Golang?
 */

#define CHECK_SOCKET_CREATED(socket)                                                               \
	if (sock < 0) {                                                                            \
		ERR_NO("Failed to create socket");                                                 \
		return TEST_FAIL;                                                                  \
	}
#define CHECK_TX_TIMESTAMP(err)                                                                    \
	if (err < 0) {                                                                             \
		ERR_NO("Failed to send message or get TX timestamp");                              \
		return TEST_FAIL;                                                                  \
	}
#define CHECK_TX_NOT_ZERO(ns)                                                                      \
	if (ns == 0) {                                                                             \
		ERR("TX timestamp not found");                                                     \
		return TEST_FAIL;                                                                  \
	}

typedef Result (*test_func_t)(char *, char *, enum delay_mechanism, int);

typedef struct {
	char *name;
	char *expect;
	test_func_t func;
	enum timestamp_type tstype;
} test_t;

int setup_socket(struct pkt_cfg *cfg, char *tx_iface)
{
	int sock, err;

	sock = open_socket(tx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 0);
	if (sock < 0) {
		ERR_NO("failed to open socket");
		return -errno;
	}

	err = sk_timestamping_init(sock, tx_iface, cfg->clk_type, cfg->tstype, TRANS_IEEE_802_3, -1,
				   cfg->domain, cfg->dm, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return -errno;
	}

	return sock;
}

struct pkt_cfg init_cfg(enum timestamp_type tstype, enum hwtstamp_clk_types clk_type,
			enum delay_mechanism dm, int vlan)
{
	struct pkt_cfg c = { 0 };

	c.transportSpecific = 0;
	c.twoStepFlag_set = 0;
	c.nonstop_flag = 0;
	c.tstamp_all = 0;
	c.rx_only = 0;
	c.listen = -1;

	c.version = 2;
	c.domain = TSTEST_CHECK_DOMAIN;
	c.tstype = tstype;
	c.count = 1;
	c.seq = TSTEST_CHECK_SEQ_NR;
	c.dm = dm;
	c.clk_type = clk_type;
	if (vlan >= 0) {
		c.vlan = vlan;
		c.prio = TSTEST_CHECK_VLAN_PRIO;
	}

	return c;
}

Result check_bc_tx_sync_twostep(char *tx_port, char *rx_port, enum delay_mechanism dm, int vlan)
{
	union Message msg;
	struct pkt_cfg c;
	int sock, err;
	int64_t ns = 0;

	c = init_cfg(TS_HARDWARE, HWTSTAMP_CLOCK_TYPE_BOUNDARY_CLOCK, dm, vlan);
	/* c = init_cfg(TS_SOFTWARE, HWTSTAMP_CLOCK_TYPE_BOUNDARY_CLOCK, dm, vlan); */
	sock = setup_socket(&c, tx_port);
	CHECK_SOCKET_CREATED(sock);

	str2mac("01:1B:19:00:00:00", c.mac);
	msg = build_msg(&c, SYNC);
	err = send_msg(&c, sock, &msg, &ns);
	CHECK_TX_TIMESTAMP(err);
	CHECK_TX_NOT_ZERO(ns);

	sk_timestamping_destroy(sock, tx_port, c.tstype);
	close(sock);

	return TEST_PASS;
}

/* Any test with TS_HARDWARE can be run on TS_SOFTWARE too */
test_t tests[] = { { .name = "BC TX Sync Twostep",
		     .expect = "TX timestamp from Sync",
		     .func = check_bc_tx_sync_twostep,
		     .tstype = TS_HARDWARE },
		   { .name = NULL } };

int check_num_tests()
{
	int i;
	for (i = 0; tests[i].name != NULL; i++) {
	}
	return i;
}

int check_run_all_tests_vlan(char *tx_port, char *rx_port, int vlan)
{
	int pass = 0;
	Result res;
	int i;

	if (vlan >= 0)
		printf("===== Tagged: VLAN %d. PRIO %d =====\n", vlan, TSTEST_CHECK_VLAN_PRIO);
	else
		printf("===== Untagged =====\n");

	for (i = 0; tests[i].name != NULL; i++) {
		/* printf("Test: %s\n", tests[i].name); */
		/* printf("Test: %s ", tests[i].name); */
		/* fflush(stdout); */
		res = tests[i].func(tx_port, rx_port, DM_P2P, vlan);
		if (res == TEST_PASS) {
			printf("%s: \e[32m[PASS]\e[0m\n", tests[i].name);
			pass++;
		} else {
			printf("%s: \e[31m[FAIL]\nExpected %s\e[0m\n", tests[i].name,
			       tests[i].expect);
		}
	}

	return pass;
}

int check_run_all_tests(char *tx_port, char *rx_port)
{
	int total = 0;
	int pass = 0;

	pass += check_run_all_tests_vlan(tx_port, rx_port, -1);
	pass += check_run_all_tests_vlan(tx_port, rx_port, 0);
	pass += check_run_all_tests_vlan(tx_port, rx_port, 100);
	total = check_num_tests() * 3;

	printf("Passed %d/%d\n", pass, total);
	return pass == total;
}

/////////////////////////////////////

int send_and_receive(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type,
		     union Message **rx_msg)
{
	struct hw_timestamp hwts;
	int tx_bytes, rx_bytes;
	int64_t ns;
	int err;

	hwts.type = cfg->tstype;
	hwts.ts.ns = 0;

	tx_bytes = build_and_send(cfg, txsock, ptp_type, &hwts, &ns);
	if (tx_bytes < 0) // Convert to positive errno
		return -tx_bytes;
	rx_bytes = sk_receive(rxsock, rx_msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
	if (rx_bytes < 0) // Convert to positive errno
		return -rx_bytes;

	if (tx_bytes != rx_bytes) {
		printf("Different amount of bytes tx/rx: %d/%d\n", tx_bytes, rx_bytes);
		return TEST_FAIL;
	}

	return TEST_PASS;
}

int send_and_check(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts,
		   int expect_rx_ts)
{
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

	rx_bytes = sk_receive(rxsock, rx_msg, 1600, NULL, &hwts, 0, DEFAULT_TX_TIMEOUT);
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
	/* if (expect_tx_ts) { */
	/* printf("Got NS: %ld\n", ns); */
	/* } */

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

int check_type(struct pkt_cfg *cfg, int txsock, int rxsock, int ptp_type, int expect_tx_ts,
	       int expect_rx_ts)
{
	int err;

	err = send_and_check(cfg, txsock, rxsock, ptp_type, expect_tx_ts, expect_rx_ts);
	if (err) {
		printf("Failed %s\n", ptp_type2str(ptp_type));
		return TEST_FAIL;
	}

	return TEST_PASS;
}

int setup_sockets(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface, int *txsock, int *rxsock)
{
	int err;

	// XXX: Filters disables so we can run events and non-events on same socket
	*txsock = open_socket(tx_iface, 1, ptp_dst_mac, p2p_dst_mac, 0, 0);
	if (*txsock < 0) {
		ERR_NO("failed to open socket");
		return errno;
	}

	err = sk_timestamping_init(*txsock, tx_iface, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK,
				   cfg->tstype, TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
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

	err = sk_timestamping_init(*rxsock, rx_iface, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK,
				   cfg->tstype, TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return errno;
	}

	return 0;
}

void teardown_sockets(int txsock, int rxsock)
{
	close(txsock);
	close(rxsock);
}

void print_result(char *str, int result)
{
	if (result == TEST_PASS)
		printf("- \e[32m[Passed]\e[0m %s\n", str);
	else if (result == TEST_FAIL)
		printf("- \e[31m[Failed]\e[0m %s\n", str);
	else
		printf("- \e[31m[Error]\e[0m %s\n", str);
}

int check_onestep_ts(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
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

int check_p2p1step_ts(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
	cfg->tstype = TS_P2P1STEP;

	printf("NOT IMPLEMENTED\n");
	// TODO: Check correctionField? Potentially it could work with originTimestamp
	return 0;
}

int check_software_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_SOFTWARE;

	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	// clang-format off
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
	// clang-format on

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_hardware_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_HARDWARE;

	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	// clang-format off
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
	// clang-format on

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_onestep_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_ONESTEP;
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	str2mac("01:1B:19:00:00:00", cfg->mac);
	// clang-format off
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
	// clang-format on

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

int check_p2p1step_timestamp(struct pkt_cfg *cfg, char *tx_iface, char *rx_iface)
{
	int result = TEST_PASS;
	int txsock, rxsock;
	int64_t ns;

	cfg->tstype = TS_P2P1STEP;
	result = setup_sockets(cfg, tx_iface, rx_iface, &txsock, &rxsock);
	if (result)
		goto out;

	// clang-format off
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
	// clang-format on

out:
	teardown_sockets(txsock, rxsock);
	return result;
}

// TODO: Implement argument handling
int run_check_mode(int argc, char **argv)
{
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

	check_run_all_tests(tx_iface, rx_iface);

	return result;
}
