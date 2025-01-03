// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#ifndef __TSTEST_PKT_H__
#define __TSTEST_PKT_H__

#include <signal.h>
#include <poll.h>

#include "net_tstamp_cpy.h"
#include "timestamping.h"
#include "tstest.h"
#include "stats.h"

#define SEQUENCE_MAX 100

struct pkt_cfg {
	//int so_timestamping_flags;
	int transportSpecific;
	int twoStepFlag_set;
	int ingressLatency;
	int egressLatency;
	int nonstop_flag;
	int twoStepFlag;
	int tstamp_all;
	int auto_fup;
	int interval;
	int rx_only;
	int version;
	int listen;
	int domain;
	int tstype;
	int count;
	int vlan;
	int prio;
	int seq;
	unsigned char mac[ETH_ALEN];
	char *interface;
	int sequence_types[SEQUENCE_MAX];
	int sequence_length;
	enum delay_mechanism dm;
	enum hwtstamp_clk_types clk_type;
};

enum {
	FD_EVENT,
	FD_GENERAL,
	FD_DELAY_TIMER,
	FD_ANNOUNCE_TIMER,
	FD_SYNC_TX_TIMER,
	/* FD_SYNC_RX_TIMER, */
	/* FD_QUALIFICATION_TIMER, */
	/* FD_MANNO_TIMER, */
	/* FD_SYNC_TX_TIMER, */
	/* FD_UNICAST_REQ_TIMER, */
	/* FD_UNICAST_SRV_TIMER, */
	/* FD_RTNL, */
	N_POLLFD,

};

/* Forward declaration */
typedef struct port Port;

typedef int (*event_t)(Port *port, int fd_index);

struct port {
	struct pkt_cfg cfg;
	int g_sock;
	int e_sock;
	struct pollfd pollfd[N_POLLFD];
	event_t ev_handler;
	bool do_record;
	PortRecord record;
};

int is_running();
void sig_handler(int sig);

int msg_get_type(union Message *msg);
int msg_is_onestep(union Message *msg);
int64_t msg_get_origin_timestamp(union Message *msg);
union Message build_msg(struct pkt_cfg *cfg, int type);
int send_msg(struct pkt_cfg *cfg, int sock, union Message *msg, int64_t *ns);
int build_and_send(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts, int64_t *ns);

/* int port_poll(Port *port); */
int port_clear_timer(Port *port, int fd_index);
int port_set_timer(Port *port, int fd_index, int interval_ms);
int port_poll(Port *port);
int port_event(Port *port, int fd_index);
int port_init(Port *port, struct pkt_cfg cfg, char *portname, event_t ev_handler, bool do_record,
	      bool open_evsock, bool open_gensock);
int port_free(Port *port);
int port_clear_record(Port *port);

#endif /* __TSTEST_PKT_H__ */
