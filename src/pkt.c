// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "liblink.h"
#include "pkt.h"
#include "stats.h"

/* TODO:
 * - Fix tstamp-all
 */

static volatile int running = 1;

int is_running()
{
	return running;
}

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

void pkt_help()
{
	fprintf(stderr, "\n--- TSTest Packets ---\n\n");
	fprintf(stderr, "Transmits and receives PTP packets and outputs the timestamps\n\n\
Usage:\n\
        tstest pkt [options]\n\n\
Options:\n\
        -i <interface>\n\
        -T <PTP type>. Can be repeated to create a sequence of packets\n\
        -r Only listen to incoming packets\n\
	-a Timestamp all packets (CURRENTLY NOT WORKING)\n\
        -D <domain>. PTP domain number\n\
        -o Use one-step timestamping\n\
        -O Use p2p-one-step timestamping\n\
        -S Use sofware timestamping\n\
        -s <sequence id>. Start PTP sequence ID at this value.\n\
        -m <destination MAC>\n\
        -c <frame counts>. Set to 0 to send until stopped\n\
	-l <0|1>. 0: Never fetch timestamp. 1: Always fetch timestamp (even for types that might not have)\n\
        -d Enable debug output\n\
	-v <2|2.1> PTP version of the packet\n\
        -h help\n\
	--transportSpecific <value>. Set value for the transportSpecific field\n\
	--twoStepFlag <0|1>. Force if twoStepFlag should be set or not. Default is automatic\n\
        \n");
}

void sig_handler(int sig)
{
	running = 0;
}

static void set_two_step_flag(struct pkt_cfg *cfg, struct ptp_header *hdr, int type)
{
	int twoStepFlag = 0x00;

	if (cfg->twoStepFlag_set) {
		// Manually control two-step flag
		if (cfg->twoStepFlag)
			twoStepFlag = 0x02;
		else
			twoStepFlag = 0x00;
	} else {
		if (type == SYNC && cfg->tstype != TS_ONESTEP && cfg->tstype != TS_P2P1STEP)
			twoStepFlag = 0x02;
		else if (type == PDELAY_RESP && cfg->tstype != TS_P2P1STEP)
			twoStepFlag = 0x02;
	}

	ptp_set_flags(hdr, twoStepFlag);
}

static int get_event_type(struct pkt_cfg *cfg, int type)
{
	if (cfg->listen == 1) // Force listen
		return TRANS_EVENT;
	if (cfg->listen == 0) // Force quiet
		return TRANS_GENERAL;

	if (type == PDELAY_REQ)
		return TRANS_EVENT; // Always timestamp pdelay_req
	else if (cfg->tstype == TS_P2P1STEP && type == PDELAY_RESP)
		return TRANS_GENERAL; // Don't timestamp pdelay_resp on p2p1step
	else if ((cfg->tstype == TS_ONESTEP || cfg->tstype == TS_P2P1STEP) && type == SYNC)
		return TRANS_GENERAL; // Don't timestamp sync on onestep and p2p1step
	else if (type & 0x8)
		return TRANS_GENERAL; // Don't timestamp general packets
	else
		return TRANS_EVENT; // Timestamp rest
}

int msg_get_type(union Message *msg)
{
	return msg->hdr.tsmt & 0xF;
}

int msg_is_onestep(union Message *msg)
{
	return !(msg->hdr.flagField[0] & 0x02);
}

union Message build_msg(struct pkt_cfg *cfg, int type)
{
	struct ptp_header hdr;

	hdr = ptp_header_template();
	ptp_set_type(&hdr, type);
	ptp_set_seqId(&hdr, cfg->seq);
	ptp_set_dmac(&hdr, (unsigned char *)cfg->mac);
	ptp_set_transport_specific(&hdr, cfg->transportSpecific);
	ptp_set_version(&hdr, cfg->version);
	ptp_set_domain(&hdr, cfg->domain);

	set_two_step_flag(cfg, &hdr, type);

	return ptp_msg_create_type(hdr, type);
}

int send_msg(struct pkt_cfg *cfg, int sock, union Message *msg, int64_t *ns)
{
	int type = msg_get_type(msg);
	int event_type, size, err;
	struct hw_timestamp hwts;
	char buf[1500];
	uint16_t *dot1q, *vid;

	hwts.type = cfg->tstype;
	event_type = get_event_type(cfg, type);
	size = ptp_msg_get_size(type);
	memset(buf, 0, 1500);
	memcpy(buf, msg, size);
	if (cfg->vlan != 0 || cfg->prio != 0) {
		size += 4;
		memmove(&buf[16], &buf[12], 1484);
		dot1q = (uint16_t *)&buf[12];
		vid = (uint16_t *)&buf[14];
		*dot1q = htons(ETH_P_8021Q);
		*vid = htons((cfg->prio << 13) | cfg->vlan);
	}

	err = raw_send(sock, event_type, buf, size, &hwts);
	*ns = hwts.ts.ns;
	return err;
}

int build_and_send(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts, int64_t *ns)
{
	struct ptp_header hdr;
	union Message tx_msg;
	int event_type;
	int err;

	tx_msg = build_msg(cfg, type);
	return send_msg(cfg, sock, &tx_msg, ns);
}

static int send_print(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts)
{
	enum transport_event event_type;
	int64_t ns;
	int err;

	err = build_and_send(cfg, sock, type, hwts, &ns);
	print_ts("TS: ", ns);
	return err;
}

static int send_auto_fup(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts)
{
	struct ptp_header hdr;
	union Message msg;
	int ptp_type;
	int err;

	if (type == SYNC)
		type = FOLLOW_UP;
	else if (type == PDELAY_RESP)
		type = PDELAY_RESP_FUP;
	else
		return -EINVAL;

	return send_print(cfg, sock, ptp_type, hwts);
}

int sk_get_error(int fd)
{
	socklen_t len;
	int error;

	len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
		ERR("getsockopt SO_ERROR failed: %m");
		return -1;
	}

	return error;
}

int port_clear_timer(Port *port, int fd_index)
{
	struct itimerspec tmo = { { 0, 0 }, { 0, 0 } };
	return timerfd_settime(port->pollfd[fd_index].fd, 0, &tmo, NULL);
}

int port_set_timer(Port *port, int fd_index, int interval_ms)
{
	struct itimerspec tmo = { { 0, 0 }, { 0, 0 } };
	int seconds = 0;

	seconds = interval_ms / 1000;
	interval_ms = interval_ms % 1000;

	tmo.it_value.tv_sec = 0;
	tmo.it_value.tv_nsec = 1000000 * 100;
	tmo.it_interval.tv_sec = seconds;
	tmo.it_interval.tv_nsec = 1000000 * interval_ms;
	return timerfd_settime(port->pollfd[fd_index].fd, 0, &tmo, NULL);
}

int port_poll(Port *port)
{
	int res;
	int cnt;

	struct pollfd *cur;
	cnt = poll(port->pollfd, N_POLLFD, 1);
	cur = port->pollfd;
	for (int i = 0; i < N_POLLFD; i++) {
		if (cur[i].revents & (POLLIN | POLLPRI | POLLERR)) {
			if (cur[i].revents & POLLERR) {
				int error = sk_get_error(cur[i].fd);
				ERR("%s: error on fda[%d]: %s", port->cfg.interface, i,
				    strerror(error));
				continue;
			}
			res = port->ev_handler(port, i);
		}
	}
	return 0;
}

static int port_open_sockets(Port *port, bool open_evsock, bool open_gensock)
{
	int e_sock = -1, g_sock = -1, err;

	if (open_evsock) {
		e_sock = open_socket(port->cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
		if (e_sock < 0)
			return e_sock;
		err = sk_timestamping_init(e_sock, port->cfg.interface,
					   HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK, port->cfg.tstype,
					   TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
		if (err < 0)
			return -err;
	}

	if (open_gensock) {
		g_sock = open_socket(port->cfg.interface, 0, ptp_dst_mac, p2p_dst_mac, 0, 1);
		if (g_sock < 0)
			return g_sock;
	}

	port->e_sock = e_sock;
	port->g_sock = g_sock;
	return 0;
}

static void port_close_sockets(Port *port)
{
	sk_timestamping_destroy(port->e_sock, port->cfg.interface, port->cfg.tstype);
	close(port->e_sock);
	close(port->g_sock);
	port->e_sock = -1;
	port->g_sock = -1;
}

static void fd_init(struct pollfd *pollfd, int fd_index, int fd)
{
	pollfd[fd_index].fd = fd;
	pollfd[fd_index].events = POLLIN | POLLPRI;
}

int port_init(Port *port, struct pkt_cfg cfg, char *portname, event_t ev_handler, bool do_record,
	      bool open_evsock, bool open_gensock)
{
	int err;
	int fd;

	memset(port, 0, sizeof(Port));

	cfg.interface = portname;
	port->cfg = cfg;
	port->ev_handler = ev_handler;
	err = port_open_sockets(port, open_evsock, open_gensock);
	if (err)
		return err;
	if (do_record) {
		port->do_record = true;
		err = record_init(&port->record, cfg.interface, 0);
		if (err)
			goto out_close_sockets;
	}

	fd_init(port->pollfd, FD_EVENT, port->e_sock);
	fd_init(port->pollfd, FD_GENERAL, port->g_sock);

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		ERR("Failed to create SYNC TX TIMER\n");
		goto out_free_record;
	}
	for (int fd_index = FD_DELAY_TIMER; fd_index < N_POLLFD; fd_index++) {
		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd < 0) {
			ERR("timerfd_create: %s", strerror(errno));
			goto out_free_record;
		}
		fd_init(port->pollfd, fd_index, fd);
	}

	return 0;

out_free_record:
	record_free(&port->record);
out_close_sockets:
	port_close_sockets(port);
	return err;
}

int port_clear_record(Port *port)
{
	if (!port->do_record)
		return 0;
	record_free(&port->record);
	return record_init(&port->record, port->cfg.interface, 0);
}

int port_free(Port *port)
{
	int err;

	port_close_sockets(port);
	record_free(&port->record);
	return 0;
}

static void tx_mode(struct pkt_cfg *cfg, int sock, struct hw_timestamp *hwts)
{
	int type;
	int i;

	while (cfg->count || cfg->nonstop_flag) {
		for (i = 0; i < cfg->sequence_length; i++) {
			type = cfg->sequence_types[i];
			send_print(cfg, sock, type, hwts);
			if (cfg->auto_fup && (type == SYNC || type == PDELAY_RESP)) {
				/* Allow the sync to send first to avoid out-of-order */
				usleep(50000);
				send_auto_fup(cfg, sock, type, hwts);
			}
			cfg->seq++;
		}
		// Not working
		if (!cfg->nonstop_flag)
			cfg->count--;
	}
}

static void rx_mode(struct pkt_cfg *cfg, int sock, struct hw_timestamp *hwts)
{
	unsigned char buf[1600];
	union Message *rx_msg;
	struct timeval timeout;
	int cnt;

	rx_msg = (union Message *)buf;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
		ERR("setsockopt failed: %m\n");

	while (running) {
		cnt = sk_receive(sock, rx_msg, 1600, NULL, hwts, 0, DEFAULT_TX_TIMEOUT);
		if (cnt < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		printf("Type: %s. ", ptp_type2str(rx_msg->hdr.tsmt & 0xF));
		print_ts("TS: ", hwts->ts.ns);
	}
}

static int pkt_parse_opt(int argc, char **argv, struct pkt_cfg *cfg)
{
	int type;
	int c;

	str2mac("ff:ff:ff:ff:ff:ff", cfg->mac);
	cfg->tstype = TS_HARDWARE;
	cfg->version = 2 | (1 << 4);
	cfg->twoStepFlag = 1;
	cfg->count = 1;
	cfg->listen = -1;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 { "twoStepFlag", required_argument, NULL, 2 },
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		pkt_help();
		return EINVAL;
	}

	while ((c = getopt_long(argc, argv, "StrapdfD:l:hoOi:m:c:s:T:v:", long_options, NULL)) !=
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
			if (cfg->sequence_length >= SEQUENCE_MAX) {
				printf("Sequence too long. Max %d\n", SEQUENCE_MAX);
				return -1;
			}

			type = str2ptp_type(optarg);
			if (type < 0) {
				printf("Invalid ptp type\n");
				printf("Expected: sync|follow_up|delay_req|delay_resp|pdelay_req|pdelay_resp|pdelay_resp_fup|announce|management|signaling\n");
				return -1;
			}
			cfg->sequence_types[cfg->sequence_length] = type;
			cfg->sequence_length++;
			break;
		case 'S':
			cfg->tstype = TS_SOFTWARE;
			break;
		case 'a':
			cfg->tstamp_all = 1;
			break;
		case 'o':
			cfg->tstype = TS_ONESTEP;
			break;
		case 'O':
			cfg->tstype = TS_P2P1STEP;
			break;
		case 'l':
			// Force listen or not listen to TS
			cfg->listen = strtol(optarg, NULL, 0);
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

	if (cfg->sequence_length == 0) {
		cfg->sequence_types[0] = SYNC;
		cfg->sequence_length = 1;
	}

	return 0;
}

int run_pkt_mode(int argc, char **argv)
{
	enum transport_event event_type;
	struct pkt_cfg cfg = { 0 };
	struct hw_timestamp hwts;
	int sock;
	int err;

	err = pkt_parse_opt(argc, argv, &cfg);
	if (err)
		return err;

	if (!cfg.interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	/*if (cfg.auto_fup && (cfg.ptp_type != SYNC && cfg.ptp_type != PDELAY_RESP)) {*/
	/*fprintf(stderr,*/
	/*"Error: auto-follow-up can only be used with sync and pdelay_resp\n");*/
	/*return EINVAL;*/
	/*}*/

	signal(SIGINT, sig_handler);

	if (!cfg.count)
		cfg.nonstop_flag = 1;

	/* Using this new method the tstamp_all will not work. Will
	 * pdelay_req/resp work correctly with one-step/p2p1step?
	 */

	hwts.type = cfg.tstype;
	hwts.ts.ns = 0;
	sock = open_socket(cfg.interface, 1, ptp_dst_mac, p2p_dst_mac, 0, 1);
	if (sock < 0) {
		ERR_NO("failed to open socket");
		return sock;
	}

	err = sk_timestamping_init(sock, cfg.interface, HWTSTAMP_CLOCK_TYPE_ORDINARY_CLOCK,
				   cfg.tstype, TRANS_IEEE_802_3, -1, 0, DM_P2P, 0);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	if (cfg.rx_only)
		rx_mode(&cfg, sock, &hwts);
	else
		tx_mode(&cfg, sock, &hwts);

	sk_timestamping_destroy(sock, cfg.interface, cfg.tstype);

	return 0;
}
