// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "pkt.h"
#include "liblink.h"
#include "stats.h"

/* TODO:
 * - If performance becomes slow, aggregate all calculations into one
     loop and return a struct with all results.
 */

static void print_tsinfo(struct tsinfo *tsinfo)
{
	DEBUG("------------------\n");
	DEBUG("TSINFO Type     %s\n", ptp_type2str(tsinfo->ptp_type));
	DEBUG("TSINFO Seq      %u\n", tsinfo->seqid);
	DEBUG("TSINFO src_self %u\n", tsinfo->src_is_self);
	DEBUG("TSINFO TX_TS    %" PRId64 "\n", tsinfo->tx_ts);
	DEBUG("TSINFO RX_TS    %" PRId64 "\n", tsinfo->rx_ts);
	DEBUG("TSINFO CORR     %" PRId64 "\n", tsinfo->correction);
}

static void print_message_record(char *port, MessageRecord *m)
{
	DEBUG("----- Port %s ---------\n", port);
	DEBUG("MR Type     %s\n", ptp_type2str(m->ptp_type));
	DEBUG("MR Seq      %u\n", m->seqid);
	DEBUG("MR src_self %u\n", m->src_is_self);
	DEBUG("MR TX_TS    %" PRId64 "\n", m->tx_ts);
	DEBUG("MR RX_TS    %" PRId64 "\n", m->rx_ts);
}

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
	s->count = 0;
	s->size = 0;
	s->tsinfo = NULL;
}

/* int stats_add(Stats *s, int64_t tx_ts, int64_t rx_ts, int64_t correction, uint16_t seqid) */
int stats_add(Stats *s, struct tsinfo tsinfo)
{
	struct tsinfo *tmp;

	if (s->count == s->size) {
		s->size = s->size * 2;
		tmp = realloc(s->tsinfo, sizeof(struct tsinfo) * s->size);
		if (!tmp) {
			ERR("failed to reallocate stats array");
			return ENOMEM;
		}
		s->tsinfo = tmp;
	}

	s->tsinfo[s->count] = tsinfo;
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

/* Syncs and Delays are mapped based on sequence ID. This isn't ideal
 * if they are not sent at the same time. It would be possible to map
 * the DelayReq TX to Sync RX time. Or just send the DelayReq when a
 * Sync is received so they can be associated. But this isn't ideal
 * for BC and Pdelay.
 */

static struct tsinfo *stats_get_tsinfo(Stats *s, int ptp_type, int seqid)
{
	for (int i = 0; i < s->count; i++)
		if (s->tsinfo[i].ptp_type == ptp_type && s->tsinfo[i].seqid == seqid)
			return &s->tsinfo[i];
	return NULL;
}

static int stats_get_twoway_error(Stats *s, struct tsinfo *sync)
{
	int64_t timeerror, timeerror_delay;
	struct tsinfo *delay;
	timeerror = tsinfo_get_error(*sync);
	delay = stats_get_tsinfo(s, DELAY_REQ, sync->seqid);
	if (!delay) {
		ERR("Missing Delay for Sync with SeqID %" PRId16, sync->seqid);
		return 0;
	}
	timeerror_delay = tsinfo_get_error(*delay);
	return (timeerror + timeerror_delay) / 2;
}

/* static StatsResult stats_get_twoway_time_error(Stats *s) */
/* { */
/* 	int64_t sum_err = 0; */
/* 	int64_t timeerror, timerror_delay; */
/* 	StatsResult r; */
/* 	struct tsinfo *delay; */

/* 	timeerror = tsinfo_get_error(s->tsinfo[0]); */
/* 	r.max = timeerror; */
/* 	r.min = timeerror; */
/* 	for (int i = 0; i < s->count; i++) { */
/* 		if (s->tsinfo[i].ptp_type != SYNC) */
/* 			continue; */
/* 		timeerror = stats_get_twoway_error(s, &s->tsinfo[i]); */
/* 		if (timeerror > r.max) */
/* 			r.max = timeerror; */
/* 		if (timeerror < r.min) */
/* 			r.min = timeerror; */
/* 		sum_err += timeerror; */
/* 	} */
/* 	r.mean = sum_err / s->count; */
/* 	return r; */
/* } */

static StatsResult stats_get_time_error(Stats *s, int ptp_type)
{
	int64_t sum_err = 0;
	bool twoway = false;
	int64_t timeerror;
	StatsResult r;
	struct tsinfo *first_sync = NULL;
	int count = 0;

	if (ptp_type == -1) {
		ptp_type = SYNC;
		twoway = true;
	}

	if (twoway) {
		first_sync = stats_get_tsinfo(s, ptp_type, 0);
		if (!first_sync) {
			// TODO: Improve how this is handled. Don't base it
			// on SeqId 0.
			ERR("FAilED to find first Sync\n");
		}
		timeerror = stats_get_twoway_error(s, first_sync);
	} else {
		timeerror = tsinfo_get_error(s->tsinfo[0]);
	}
	r.max = timeerror;
	r.min = timeerror;
	for (int i = 0; i < s->count; i++) {
		if (s->tsinfo[i].ptp_type != ptp_type)
			continue;
		if (twoway)
			timeerror = stats_get_twoway_error(s, &s->tsinfo[i]);
		else
			timeerror = tsinfo_get_error(s->tsinfo[i]);
		if (timeerror > r.max)
			r.max = timeerror;
		if (timeerror < r.min)
			r.min = timeerror;
		sum_err += timeerror;
		count++;
	}
	r.mean = sum_err / count;
	return r;
}

static StatsResult stats_get_sync_time_error(Stats *s)
{
	return stats_get_time_error(s, SYNC);
}

static StatsResult stats_get_delay_time_error(Stats *s)
{
	return stats_get_time_error(s, DELAY_REQ);
}

static StatsResult stats_get_twoway_time_error(Stats *s)
{
	return stats_get_time_error(s, -1);
}

StatsResult stats_get_sync_latency(Stats *s)
{
	int64_t sum_lat = 0;
	int64_t latency;
	StatsResult r;
	int count = 0;

	latency = tsinfo_get_latency(s->tsinfo[0]);
	r.max = latency;
	r.min = latency;
	for (int i = 0; i < s->count; i++) {
		if (s->tsinfo[i].ptp_type != SYNC)
			continue;
		latency = tsinfo_get_latency(s->tsinfo[i]);
		if (latency > r.max)
			r.max = latency;
		if (latency < r.min)
			r.min = latency;
		sum_lat += latency;
		count++;
	}

	r.mean = sum_lat / count;
	return r;
}

static int64_t pdv_get_lucky_packet(Stats *s)
{
	int64_t lucky_packet, tmp;

	lucky_packet = s->tsinfo[0].rx_ts - s->tsinfo[0].tx_ts;
	for (int i = 1; i < s->count; i++) {
		if (s->tsinfo[i].ptp_type != SYNC)
			continue;
		tmp = s->tsinfo[i].rx_ts - s->tsinfo[i].tx_ts;
		if (tmp < lucky_packet)
			lucky_packet = tmp;
	}
	return lucky_packet;
}

StatsResult stats_get_sync_pdv(Stats *s)
{
	int64_t lucky_packet, tmp, sum = 0;
	StatsResult r = { 0 };

	lucky_packet = pdv_get_lucky_packet(s);
	r.max = 0;
	r.min = 0;
	for (int i = 0; i < s->count; i++) {
		if (s->tsinfo[i].ptp_type != SYNC)
			continue;
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

	if (count_left)
		printf("%d measurements (exited early, expected %d)\n", s->count,
		       s->count + count_left);
	else
		printf("%d measurements\n", s->count);
	printf("%s -> %s\n", p1, p2);

	if (debugen) {
		for (int i = 0; i < s->count; i++) {
			print_tsinfo(&s->tsinfo[i]);
		}
	}

	StatsResult sync_time_error = stats_get_sync_time_error(s);
	StatsResult delay_time_error = stats_get_delay_time_error(s);
	StatsResult twoway_time_error = stats_get_twoway_time_error(s);
	StatsResult sync_latency = stats_get_sync_latency(s);
	StatsResult sync_pdv = stats_get_sync_pdv(s);

	printf("--- SYNC TIME ERROR ---\n");
	printf("Mean: %" PRId64 "\n", sync_time_error.mean);
	printf("Max : %" PRId64 "\n", sync_time_error.max);
	printf("Min : %" PRId64 "\n", sync_time_error.min);
	printf("--- DELAY TIME ERROR ---\n");
	printf("Mean: %" PRId64 "\n", delay_time_error.mean);
	printf("Max : %" PRId64 "\n", delay_time_error.max);
	printf("Min : %" PRId64 "\n", delay_time_error.min);
	printf("--- 2-WAY TIME ERROR ---\n");
	printf("Mean: %" PRId64 "\n", twoway_time_error.mean);
	printf("Max : %" PRId64 "\n", twoway_time_error.max);
	printf("Min : %" PRId64 "\n", twoway_time_error.min);
	printf("--- LATENCY ---\n");
	printf("Mean: %" PRId64 "\n", sync_latency.mean);
	printf("Max : %" PRId64 "\n", sync_latency.max);
	printf("Min : %" PRId64 "\n", sync_latency.min);
	printf("--- PDV ---\n");
	printf("Mean: %" PRId64 "\n", sync_pdv.mean);
	printf("Max : %" PRId64 "\n", sync_pdv.max);
	printf("Min : %" PRId64 " (lucky packet)\n", sync_pdv.min);
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

int record_init(PortRecord *pr, char *portname, int size)
{
	if (size == 0)
		pr->size = 100;
	else
		pr->size = size;
	pr->count = 0;
	pr->portname = portname;
	pr->msgs = malloc(sizeof(MessageRecord) * pr->size);
	if (!pr->msgs) {
		ERR("failed to allocate stats array");
		return ENOMEM;
	}
	return 0;
}

int record_add_tx_msg(PortRecord *pr, union Message *msg, int64_t *tx_ts)
{
	int type = msg_get_type(msg);
	int prev_size = pr->size;
	MessageRecord *tmp;
	MessageRecord *new;

	if (pr->count == pr->size) {
		pr->size = pr->size * 2;
		tmp = realloc(pr->msgs, sizeof(MessageRecord) * pr->size);
		if (!tmp) {
			ERR("failed to reallocate stats array");
			return ENOMEM;
		}
		pr->msgs = tmp;
		/* 	for (int i = prev_size; i < pr->size; i++) { */
		/* 		memset(&pr->msgs[i], 0, sizeof(MessageRecord)); */
		/* 	} */
	}

	/* DEBUG("Add TX %s: tx_ts %" PRId64"\n", ptp_type2str(msg_get_type(msg)), *tx_ts); */
	new = &pr->msgs[pr->count];
	memcpy(&new->msg, msg, sizeof(union Message));
	new->ptp_type = msg_get_type(msg);
	if (tx_ts) {
		new->tx_ts = *tx_ts;
	}
	new->seqid = be16toh(msg->hdr.sequenceId);
	/* printf("Seqid %u\n", new->seqid); */
	new->rx_ts = 0;
	new->src_is_self = true;
	pr->count++;

	/* print_message_record(pr->portname, new); */
	return 0;
}

int record_add_rx_msg(PortRecord *pr, union Message *msg, int64_t *rx_ts)
{
	int type = msg_get_type(msg);
	int prev_size = pr->size;
	MessageRecord *tmp;
	MessageRecord *new;

	if (pr->count == pr->size) {
		pr->size = pr->size * 2;
		tmp = realloc(pr->msgs, sizeof(MessageRecord) * pr->size);
		if (!tmp) {
			ERR("failed to reallocate stats array");
			return ENOMEM;
		}
		pr->msgs = tmp;
		/* 	for (int i = prev_size; i < pr->size; i++) { */
		/* 		memset(&pr->msgs[i], 0, sizeof(MessageRecord)); */
		/* 	} */
	}

	new = &pr->msgs[pr->count];
	memcpy(&new->msg, msg, sizeof(union Message));
	new->ptp_type = msg_get_type(msg);
	new->rx_ts = 0;
	if (rx_ts) {
		new->rx_ts = *rx_ts;
	}
	new->seqid = be16toh(msg->hdr.sequenceId);
	new->tx_ts = 0;
	/* TODO: How should we handle onestep timestamps for pdelay? */
	if (new->ptp_type == SYNC && msg_is_onestep(msg)) {
		new->tx_ts = ptp_get_originTimestamp(msg);
	} else if (new->ptp_type == FOLLOW_UP) {
		new->tx_ts = ptp_get_originTimestamp(msg);
	}
	new->src_is_self = false;
	if (memcmp(msg->hdr.sourcePortIdentity.clockIdentity.id, ptp_default_clockid(), 8) == 0)
		new->src_is_self = true;
	pr->count++;

	/* print_message_record(pr->portname, new); */
	return 0;
}

static struct tsinfo *stats_get_record(Stats *s, uint8_t ptp_type, uint16_t seqid)
{
	for (int i = 0; i < s->count; i++) {
		if (s->tsinfo[i].ptp_type == ptp_type && s->tsinfo[i].seqid == seqid)
			return &s->tsinfo[i];
	}
	return NULL;
}

static uint8_t get_primary_type(MessageRecord *m)
{
	if (m->ptp_type == SYNC || m->ptp_type == FOLLOW_UP)
		return SYNC;
	if (m->ptp_type == DELAY_REQ || m->ptp_type == DELAY_RESP)
		return DELAY_REQ;
	if (m->ptp_type == PDELAY_REQ || m->ptp_type == PDELAY_RESP ||
	    m->ptp_type == PDELAY_RESP_FUP)
		return PDELAY_REQ;
	ERR("Unexpected PTP message type %d encountered\n", m->ptp_type);
	return m->ptp_type;
}

/* static int is_matching_types(MessageRecord *m1, MessageRecord *m2) */
/* { */
/* 	return get_primary_type(m1) == get_primary_type(m2); */
/* } */

static int record_map_msg_to_tsinfo(Stats *s, MessageRecord *m, struct tsinfo *tsinfo)
{
	if (m->tx_ts) {
		if (tsinfo->tx_ts && m->tx_ts != tsinfo->tx_ts) {
			ERR("Record and tsinfo has different tx_ts. %" PRId64 " and %" PRId64 "\n",
			    m->tx_ts, tsinfo->tx_ts);
		}
		tsinfo->tx_ts = m->tx_ts;
	}

	if (m->rx_ts) {
		if (tsinfo->rx_ts && m->rx_ts != tsinfo->rx_ts) {
			ERR("Record and tsinfo has different rx_ts. %" PRId64 " and %" PRId64 "\n",
			    m->rx_ts, tsinfo->rx_ts);
		}
		tsinfo->rx_ts = m->rx_ts;
		/* Add correction. Adjustments can be made in any packet */
		tsinfo->correction += ptp_get_correctionField(&m->msg);
	}

	if (tsinfo->ptp_type == DELAY_REQ && m->ptp_type == DELAY_RESP) {
		tsinfo->rx_ts = ptp_get_originTimestamp(&m->msg);
		tsinfo->correction = ptp_get_correctionField(&m->msg);
	}

	return 0;
}

static struct tsinfo record_msg_to_tsinfo(MessageRecord *m)
{
	struct tsinfo tsinfo = { 0 };

	tsinfo.ptp_type = get_primary_type(m);
	tsinfo.seqid = m->seqid;
	tsinfo.src_is_self = m->src_is_self;
	if (m->tx_ts) {
		tsinfo.tx_ts = m->tx_ts;
	}
	if (m->rx_ts) {
		tsinfo.rx_ts = m->rx_ts;
		tsinfo.correction = ptp_get_correctionField(&m->msg);
	}
	return tsinfo;
}

void record_map_messages(Stats *s, PortRecord *p1, PortRecord *p2)
{
	MessageRecord *m1, *m2;
	struct tsinfo *tsinfo;
	int matched = 0;

	for (int i = 0; i < p1->count; i++) {
		m1 = &p1->msgs[i];
		stats_add(s, record_msg_to_tsinfo(m1));
	}

	for (int i = 0; i < p2->count; i++) {
		m2 = &p2->msgs[i];
		tsinfo = stats_get_record(s, get_primary_type(m2), m2->seqid);
		if (!tsinfo) {
			stats_add(s, record_msg_to_tsinfo(m2));
			continue;
		}
		record_map_msg_to_tsinfo(s, m2, tsinfo);
	}
}

void record_free(PortRecord *pr)
{
	free(pr->msgs);
	pr->count = 0;
	pr->size = 0;
	pr->msgs = NULL;
}
