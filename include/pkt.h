// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2024 Casper Andersson <casper.casan@gmail.com>

#include "net_tstamp_cpy.h"
#include "timestamping.h"
#include "tstest.h"

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

int msg_get_type(union Message *msg);
int msg_is_onestep(union Message *msg);
int64_t msg_get_origin_timestamp(union Message *msg);
union Message build_msg(struct pkt_cfg *cfg, int type);
int send_msg(struct pkt_cfg *cfg, int sock, union Message *msg, int64_t *ns);
int build_and_send(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts, int64_t *ns);
