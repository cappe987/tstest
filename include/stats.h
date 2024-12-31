// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2024 Casper Andersson <casper.casan@gmail.com>

#ifndef __STATS_H__
#define __STATS_H__

#include <inttypes.h>

typedef struct {
	int64_t mean;
	int64_t max;
	int64_t min;
} Result;

/* Ingress/egress latency of host should be accounted for in these timestamps */
struct tsinfo {
	uint16_t seqid;
	int64_t tx_ts;
	int64_t rx_ts;
	int64_t correction;
};

typedef struct {
	int count;
	int size;
	struct tsinfo *tsinfo;
} Stats;

int stats_init(Stats *s, int size);
void stats_free(Stats *s);
int stats_add(Stats *s, int64_t tx_ts, int64_t rx_ts, int64_t correction, uint16_t seqid);
Result stats_get_time_error(Stats *s);
Result stats_get_latency(Stats *s);
Result stats_get_pdv(Stats *s);
void stats_show(Stats *s, char *p1, char *p2, int count_left);
void stats_output_time_error(Stats *s, char *path);

#endif /* __STATS_H__ */
