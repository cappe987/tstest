// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#ifndef __TSTEST_STATS_H__
#define __TSTEST_STATS_H__

#include <inttypes.h>
#include <stdbool.h>

#include "tstest.h"

typedef struct {
	int64_t mean;
	int64_t max;
	int64_t min;
} StatsResult;

/* Ingress/egress latency of host should be accounted for in these timestamps */
typedef struct {
	uint8_t ptp_type;
	bool src_is_self;
	uint16_t seqid;
	int64_t tx_ts;
	int64_t rx_ts;
	/* TODO: Extract correctionField */
	/* int64_t correction; */
	union Message msg;
} MessageRecord;

typedef struct {
	int count;
	int size;
	char *portname;
	MessageRecord *msgs;
} PortRecord;

typedef struct {
	uint8_t primary_type; /* Sync, DelayReq, PdelayReq, etc. */
	uint16_t seqid;
	bool src_is_self;
	MessageRecord *fst; /* Sync, DelayReq, PdelayReq, etc. */
	MessageRecord *snd; /* FollowUp, DelayResp, PdelayResp */
	MessageRecord *trd; /* PdelayRespFup */
} PacketData;

typedef struct {
	int count;
	int size;
	/* struct tsinfo *tsinfo; */
	enum delay_mechanism dm;
	PacketData *packets;
} Stats;

static PacketData *get_next_of_type(Stats *s, int *i, int type)
{
	while (*i < s->count) {
		if (s->packets[*i].primary_type == type) {
			return &s->packets[*i];
		}
		(*i)++;
	}
	return NULL;
}

#define FOREACH_PKT_TYPE(stats, type, pkt_ptr)                                                     \
	for (int i = 0; (pkt_ptr = get_next_of_type(stats, &i, type)); i++)

int stats_init(Stats *s, enum delay_mechanism dm);
void stats_free(Stats *s);
void stats_show(Stats *s, char *p1, char *p2, int count_left);
void stats_output_measurements(Stats *s, char *path);
void stats_collect_port_record(PortRecord *p, Stats *s);

int record_init(PortRecord *pr, char *portname, int size);
int record_add_tx_msg(PortRecord *pr, union Message *msg, int64_t *tx_ts);
int record_add_rx_msg(PortRecord *pr, union Message *msg, int64_t *rx_ts);
void record_free(PortRecord *pr);

#endif /* __TSTEST_STATS_H__ */
