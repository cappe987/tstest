// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2024 Casper Andersson <casper.casan@gmail.com>

#define SEQUENCE_MAX 100

struct pkt_cfg {
	//int so_timestamping_flags;
	int transportSpecific;
	int twoStepFlag_set;
	int nonstop_flag;
	int twoStepFlag;
	int tstamp_all;
	int auto_fup;
	int rx_only;
	int version;
	int listen;
	int domain;
	int tstype;
	int count;
	int seq;
	char mac[ETH_ALEN];
	char *interface;
	int sequence_types[SEQUENCE_MAX];
	int sequence_length;
};

int build_and_send(struct pkt_cfg *cfg, int sock, int type, struct hw_timestamp *hwts, int64_t *ns);
