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

int init_stats(Stats *s, int size);
void free_stats(Stats *s);
int add_stats(Stats *s, int64_t tx_ts, int64_t rx_ts, int64_t correction, uint16_t seqid);
Result stats_get_time_error(Stats *s);
Result stats_get_latency(Stats *s);
Result stats_get_pdv(Stats *s);
void show_stats(Stats *s, char *p1, char *p2, int count_left);

#endif /* __STATS_H__ */
