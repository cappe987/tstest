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
} Result;

/* Ingress/egress latency of host should be accounted for in these timestamps */
struct tsinfo {
	/* ptp_type + seqid + src_is_self constitutes a key. Only
	 * valid types are Sync, DelayReq, and PdelayReq. The
	 * follow-ups and responses are recorded with the
	 * original. I.e. Sync+FollowUp, DelayReq+DelayResp,
	 * PdelayReq+PdelayResp+PdelayRespFup
	 */
	uint8_t ptp_type;
	uint16_t seqid;
	bool src_is_self;
	int64_t tx_ts;
	int64_t rx_ts;
	int64_t correction;
	bool tx_saved;
	bool rx_saved; /* includes both rx_ts and correction */
};

typedef struct {
	int count;
	int size;
	struct tsinfo *tsinfo;
} Stats;

typedef struct {
	uint8_t ptp_type;
	bool src_is_self;
	uint16_t seqid;
	int64_t tx_ts;
	int64_t rx_ts;
	/* onestep tx_ts and correction can be extracted later */
	/* int64_t correction; */
	bool tx_saved;
	bool rx_saved;
	union Message msg;
} MessageRecord;

typedef struct {
	int count;
	int size;
	char *portname;
	MessageRecord *msgs;
} PortRecord;

int stats_init(Stats *s, int size);
void stats_free(Stats *s);
int stats_add(Stats *s, struct tsinfo tsinfo);
Result stats_get_time_error(Stats *s);
Result stats_get_latency(Stats *s);
Result stats_get_pdv(Stats *s);
void stats_show(Stats *s, char *p1, char *p2, int count_left);
void stats_output_measurements(Stats *s, char *path);

int record_init(PortRecord *pr, char *portname, int size);
int record_add_tx_msg(PortRecord *pr, union Message *msg, int64_t *tx_ts);
int record_add_rx_msg(PortRecord *pr, union Message *msg, int64_t *rx_ts);
void record_map_messages(Stats *s, PortRecord *p1, PortRecord *p2);
void record_free(PortRecord *pr);

#endif /* __TSTEST_STATS_H__ */
