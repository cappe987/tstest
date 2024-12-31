// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2024 Casper Andersson <casper.casan@gmail.com>

#include "timestamping.h"
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/if_ether.h>

#include "liblink.h"
#include "stats.h"

/* TODO:
 * - If performance becomes slow, aggregate all calculations into one
     loop and return a struct with all results.
 */

int stats_init(Stats *s, int size)
{
	if (size == 0)
		s->size = 100;
	else
		s->size = size;
	s->count = 0;
	s->tsinfo = malloc(sizeof(struct tsinfo) * s->size);
	if (!s->tsinfo) {
		ERR("failed to allocate stats array");
		return ENOMEM;
	}
	return 0;
}

void stats_free(Stats *s)
{
	free(s->tsinfo);
	s->tsinfo = NULL;
}

int stats_add(Stats *s, int64_t tx_ts, int64_t rx_ts, int64_t correction, uint16_t seqid)
{
	if (s->count == s->size) {
		s->size = s->size * 2;
		s->tsinfo = realloc(s->tsinfo, sizeof(struct tsinfo) * s->size);
		if (!s->tsinfo) {
			ERR("failed to reallocate stats array");
			return ENOMEM;
		}
	}

	s->tsinfo[s->count].seqid = seqid;
	s->tsinfo[s->count].tx_ts = tx_ts;
	s->tsinfo[s->count].rx_ts = rx_ts;
	s->tsinfo[s->count].correction = correction;
	s->count++;
	return 0;
}

static int64_t tsinfo_get_error(struct tsinfo tsinfo)
{
	return tsinfo.rx_ts - tsinfo.tx_ts - tsinfo.correction;
}

static int64_t tsinfo_get_latency(struct tsinfo tsinfo)
{
	return tsinfo.rx_ts - tsinfo.tx_ts;
}

Result stats_get_time_error(Stats *s)
{
	int64_t sum_err = 0;
	int64_t timeerror;
	Result r;

	timeerror = tsinfo_get_error(s->tsinfo[0]);
	r.max = timeerror;
	r.min = timeerror;
	for (int i = 0; i < s->count; i++) {
		timeerror = tsinfo_get_error(s->tsinfo[i]);
		if (timeerror > r.max)
			r.max = timeerror;
		if (timeerror < r.min)
			r.min = timeerror;
		sum_err += timeerror;
	}
	r.mean = sum_err / s->count;
	return r;
}

Result stats_get_latency(Stats *s)
{
	int64_t sum_lat = 0;
	int64_t latency;
	Result r;

	latency = tsinfo_get_latency(s->tsinfo[0]);
	r.max = latency;
	r.min = latency;
	for (int i = 0; i < s->count; i++) {
		latency = tsinfo_get_latency(s->tsinfo[i]);
		if (latency > r.max)
			r.max = latency;
		if (latency < r.min)
			r.min = latency;
		sum_lat += latency;
	}

	r.mean = sum_lat / s->count;
	return r;
}

static int64_t pdv_get_lucky_packet(Stats *s)
{
	int64_t lucky_packet, tmp;

	lucky_packet = s->tsinfo[0].rx_ts - s->tsinfo[0].tx_ts;
	for (int i = 1; i < s->count; i++) {
		tmp = s->tsinfo[i].rx_ts - s->tsinfo[i].tx_ts;
		if (tmp < lucky_packet)
			lucky_packet = tmp;
	}
	return lucky_packet;
}

Result stats_get_pdv(Stats *s)
{
	int64_t lucky_packet, tmp, sum = 0;
	Result r = { 0 };

	lucky_packet = pdv_get_lucky_packet(s);
	r.max = 0;
	r.min = 0;
	for (int i = 0; i < s->count; i++) {
		tmp = (s->tsinfo[i].rx_ts - s->tsinfo[i].tx_ts) - lucky_packet;
		sum += tmp;
		if (tmp > r.max)
			r.max = tmp;
	}
	r.mean = sum / s->count;
	return r;
}

void stats_show(Stats *s, char *p1, char *p2, int count_left)
{
	if (s->count == 0) {
		printf("No measurements\n");
		return;
	}

	printf("===============\n");
	if (count_left)
		printf("%d measurements (exited early, expected %d)\n", s->count,
		       s->count + count_left);
	else
		printf("%d measurements\n", s->count);
	printf("%s -> %s\n", p1, p2);

	Result time_error = stats_get_time_error(s);
	Result latency = stats_get_latency(s);
	Result pdv = stats_get_pdv(s);

	printf("--- TIME ERROR ---\n");
	printf("Mean: %" PRId64 "\n", time_error.mean);
	printf("Max : %" PRId64 "\n", time_error.max);
	printf("Min : %" PRId64 "\n", time_error.min);
	printf("--- LATENCY ---\n");
	printf("Mean: %" PRId64 "\n", latency.mean);
	printf("Max : %" PRId64 "\n", latency.max);
	printf("Min : %" PRId64 "\n", latency.min);
	printf("--- PDV ---\n");
	printf("Mean: %" PRId64 "\n", pdv.mean);
	printf("Max : %" PRId64 "\n", pdv.max);
	printf("Min : %" PRId64 " (lucky packet)\n", pdv.min);
	printf("===============\n");
}

static int ts_sec(int64_t ts)
{
	return ts / NS_PER_SEC;
}

static int ts_msec(int64_t ts)
{
	return (ts / 1000000) % 1000;
}

static void write_val_to_file(Stats *s, FILE *fp, struct tsinfo *tsinfo, int64_t val)
{
	int64_t curr_time;
	curr_time = tsinfo->tx_ts - s->tsinfo[0].tx_ts;
	fprintf(fp, "%d.%03d %" PRId64 "\n", ts_sec(curr_time), ts_msec(curr_time), val);
}

/* XXX: Should we output raw values instead? If we have a lot of
 * measurements it might be easier to let external software do the
 * calculations it wants to plot.
 */
void stats_output_measurements(Stats *s, char *path)
{
	int64_t base_time, curr_time, val, lucky_packet;
	FILE *fp;

	base_time = s->tsinfo[0].tx_ts;

	fp = fopen(path, "w");
	if (!fp) {
		ERR("failed opening file %s: %m", path);
		return;
	}

	fprintf(fp, "TIMEERROR\n");
	for (int i = 0; i < s->count; i++) {
		val = tsinfo_get_error(s->tsinfo[i]);
		write_val_to_file(s, fp, &s->tsinfo[i], val);
	}
	fprintf(fp, "\n");
	fprintf(fp, "LATENCY\n");
	for (int i = 0; i < s->count; i++) {
		val = tsinfo_get_latency(s->tsinfo[i]);
		write_val_to_file(s, fp, &s->tsinfo[i], val);
	}
	fprintf(fp, "\n");
	fprintf(fp, "PDV\n");
	lucky_packet = pdv_get_lucky_packet(s);
	for (int i = 0; i < s->count; i++) {
		val = (s->tsinfo[i].rx_ts - s->tsinfo[i].tx_ts) - lucky_packet;
		write_val_to_file(s, fp, &s->tsinfo[i], val);
	}
	fclose(fp);
}
