// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include "timestamping.h"
#include "tstest.h"
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "liblink.h"
#include "stats.h"
#include "pkt.h"

/* TODO:
 * - If performance becomes slow, aggregate all calculations into one
     loop and return a struct with all results.
 */

/* Syncs and Delays are mapped based on sequence ID. This isn't ideal
 * if they are not sent at the same time. It would be possible to map
 * the DelayReq TX to Sync RX time. Or just send the DelayReq when a
 * Sync is received so they can be associated. But this isn't ideal
 * for BC and Pdelay.
 *
* Keep track of current delay/pdelay and record that along with a
* received Sync. Do we need to discard the first couple measurements?
 */

static void print_message_record(char *port, MessageRecord *m)
{
	DEBUG("----- Port %s ---------\n", port);
	DEBUG("MR Type     %s\n", ptp_type2str(m->ptp_type));
	DEBUG("MR Seq      %u\n", m->seqid);
	DEBUG("MR src_self %u\n", m->src_is_self);
	DEBUG("MR TX_TS    %" PRId64 "\n", m->tx_ts);
	DEBUG("MR RX_TS    %" PRId64 "\n", m->rx_ts);
}

int stats_init(Stats *s, enum delay_mechanism dm)
{
	s->size = 100;
	s->count = 0;
	s->dm = dm;
	s->packets = malloc(sizeof(PacketData) * s->size);
	if (!s->packets) {
		ERR("failed to allocate stats array");
		return ENOMEM;
	}
	return 0;
}

void stats_free(Stats *s)
{
	free(s->packets);
	s->count = 0;
	s->size = 0;
	s->packets = NULL;
}

static int ts_sec(int64_t ts)
{
	return ts / NS_PER_SEC;
}

static int ts_msec(int64_t ts)
{
	return (ts / 1000000) % 1000;
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

void record_free(PortRecord *pr)
{
	free(pr->msgs);
	pr->count = 0;
	pr->size = 0;
	pr->msgs = NULL;
}

MessageRecord *record_get_latest(PortRecord *pr, int type, uint16_t *seqid)
{
	int i;

	for (i = pr->count - 1; i >= 0; i--) {
		if (pr->msgs[i].ptp_type == type) {
			if (!seqid)
				return &pr->msgs[i];
			else if (pr->msgs[i].seqid == *seqid)
				return &pr->msgs[i];
		}
	}
	return NULL;
}

MessageRecord *record_get_last_added(PortRecord *pr)
{
	if (pr->count == 0)
		return NULL;
	return &pr->msgs[pr->count - 1];
}

MessageRecord *port_get_saved(Port *p, int type)
{
	int idx = -1;

	switch (type) {
	case SYNC:
		idx = p->sync >= 0 ? p->sync : -1;
		break;
	case FOLLOW_UP:
		idx = p->fup >= 0 ? p->fup : -1;
		break;
	case DELAY_REQ:
		idx = p->dreq >= 0 ? p->dreq : -1;
		break;
	case DELAY_RESP:
		idx = p->dresp >= 0 ? p->dresp : -1;
		break;
	case PDELAY_REQ:
		idx = p->pdreq >= 0 ? p->pdreq : -1;
		break;
	case PDELAY_RESP:
		idx = p->pdresp >= 0 ? p->pdresp : -1;
		break;
	case PDELAY_RESP_FUP:
		idx = p->pdresp_fup >= 0 ? p->pdresp_fup : -1;
		break;
	default:
		return NULL;
	}
	if (idx == -1)
		return NULL;
	return &p->record.msgs[idx];
}

void port_save_last_added(Port *p)
{
	MessageRecord *last = record_get_last_added(&p->record);
	int idx = p->record.count - 1;

	switch (last->ptp_type) {
	case SYNC:
		p->sync = idx;
		break;
	case FOLLOW_UP:
		p->fup = idx;
		break;
	case DELAY_REQ:
		p->dreq = idx;
		break;
	case DELAY_RESP:
		p->dresp = idx;
		break;
	case PDELAY_REQ:
		p->pdreq = idx;
		break;
	case PDELAY_RESP:
		p->pdresp = idx;
		break;
	case PDELAY_RESP_FUP:
		p->pdresp_fup = idx;
		break;
	default:
		break;
	}
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

static uint8_t get_primary_type(MessageRecord *m)
{
	if (m->ptp_type == SYNC || m->ptp_type == FOLLOW_UP)
		return SYNC;
	if (m->ptp_type == DELAY_REQ || m->ptp_type == DELAY_RESP)
		return DELAY_REQ;
	if (m->ptp_type == PDELAY_REQ || m->ptp_type == PDELAY_RESP ||
	    m->ptp_type == PDELAY_RESP_FUP)
		return PDELAY_REQ;
	/* ERR("Unexpected PTP message type %d encountered\n", m->ptp_type); */
	return m->ptp_type;
}

static PacketData *stats_get_matching(Stats *s, MessageRecord *msg)
{
	PacketData *pkt;

	for (int i = 0; i < s->count; i++) {
		pkt = &s->packets[i];
		if (pkt->primary_type == get_primary_type(msg) && pkt->seqid == msg->seqid)
			return pkt;
	}
	return NULL;
}

static void stats_assign_msg(PacketData *pkt, MessageRecord *msg)
{
	if (msg->ptp_type == FOLLOW_UP || msg->ptp_type == DELAY_RESP ||
	    msg->ptp_type == PDELAY_RESP) {
		pkt->snd = msg;
	} else if (msg->ptp_type == PDELAY_RESP_FUP) {
		pkt->trd = msg;
	} else {
		pkt->fst = msg;
		pkt->seqid = msg->seqid;
	}
	pkt->primary_type = get_primary_type(msg);
}

static int stats_add_new(Stats *s, MessageRecord *msg)
{
	PacketData *tmp;

	if (s->count == s->size) {
		s->size = s->size * 2;
		tmp = realloc(s->packets, sizeof(PacketData) * s->size);
		if (!tmp) {
			ERR("failed to reallocate stats array");
			return ENOMEM;
		}
		s->packets = tmp;
	}

	stats_assign_msg(&s->packets[s->count], msg);
	s->count++;
	return 0;
}

static int stats_add_msg(Stats *s, MessageRecord *msg)
{
	PacketData *pkt = stats_get_matching(s, msg);

	if (!pkt)
		return stats_add_new(s, msg);

	stats_assign_msg(pkt, msg);
	return 0;
}

void stats_collect_port_record(PortRecord *p, Stats *s)
{
	MessageRecord *m;

	for (int i = 0; i < p->count; i++) {
		m = &p->msgs[i];
		stats_add_msg(s, m);
	}
}

static int64_t tc_get_latency(PacketData *pkt)
{
	if (msg_is_onestep(&pkt->fst->msg))
		return pkt->fst->rx_ts - pkt->fst->tx_ts;
	else
		return pkt->fst->rx_ts - ptp_get_originTimestamp(&pkt->snd->msg);
}

static PacketData *stats_get_data(Stats *s, int ptp_type, int seqid)
{
	for (int i = 0; i < s->count; i++)
		if (s->packets[i].primary_type == ptp_type && s->packets[i].seqid == seqid)
			return &s->packets[i];
	return NULL;
}

static int64_t tc_sync_get_tx_ts(PacketData *sync)
{
	if (msg_is_onestep(&sync->fst->msg))
		return ptp_get_originTimestamp(&sync->fst->msg);
	else
		return ptp_get_originTimestamp(&sync->snd->msg);
}

/* Works for BC too */
static int64_t tc_get_oneway_error(PacketData *pkt, bool measured_link_delay)
{
	int64_t val;

	if (pkt->primary_type == SYNC) {
		if (msg_is_onestep(&pkt->fst->msg))
			/* val = pkt->fst->rx_ts - pkt->fst->tx_ts - */
			/* ptp_get_correctionField(&pkt->fst->msg); */
			val = pkt->fst->tx_ts - pkt->fst->rx_ts -
			      ptp_get_correctionField(&pkt->fst->msg);
		else
			/* val = pkt->fst->rx_ts - ptp_get_originTimestamp(&pkt->snd->msg) - */
			/*       ptp_get_correctionField(&pkt->fst->msg) - */
			/*       ptp_get_correctionField(&pkt->snd->msg); */
			val = ptp_get_originTimestamp(&pkt->snd->msg) - pkt->fst->rx_ts -
			      ptp_get_correctionField(&pkt->fst->msg) -
			      ptp_get_correctionField(&pkt->snd->msg);
		if (measured_link_delay)
			return val - pkt->fst->current_delay;
		else
			return val;
	} else if (pkt->primary_type == DELAY_REQ) {
		val = ptp_get_originTimestamp(&pkt->snd->msg) - pkt->fst->tx_ts -
		      ptp_get_correctionField(&pkt->fst->msg) -
		      ptp_get_correctionField(&pkt->snd->msg);
		if (measured_link_delay)
			return val - pkt->fst->current_delay;
		else
			return val;
	}
	ERR("Unhandled case in %s", __func__);
	return INT64_MIN;
}

static int tc_get_twoway_error(Stats *s, PacketData *sync, bool use_t4, bool measured_link_delay)
{
	int64_t timeerror, timeerror_delay;
	PacketData *delay;

	timeerror = tc_get_oneway_error(sync, false);
	if (measured_link_delay)
		return timeerror - sync->fst->current_delay;
	else if (use_t4)
		return (timeerror + sync->fst->current_t4) / 2;

	delay = stats_get_data(s, DELAY_REQ, sync->seqid);
	if (!delay) {
		ERR("Missing Delay for Sync with SeqID %" PRId16, sync->seqid);
		return 0;
	}
	timeerror_delay = tc_get_oneway_error(delay, false);
	return (timeerror + timeerror_delay) / 2;
}

static int64_t tc_get_time_error(Stats *s, PacketData *pkt, bool twoway, bool use_t4,
				 bool measured_link_delay)
{
	if (twoway)
		return tc_get_twoway_error(s, pkt, use_t4, measured_link_delay);
	else
		return tc_get_oneway_error(pkt, measured_link_delay);
}

/* 
 * Measured link delay will subtract the current delay from the
 * calculate offset.
 * 
 * Use_t4 will calculate twoway time error by doing (T1TE + T4TE) / 2.
 *
 * These two options do not work for `tstest tc` right now.
*/
static StatsResult stats_get_time_error(Stats *s, int ptp_type, bool use_t4,
					bool measured_link_delay)
{
	StatsResult r = { 0 };
	bool twoway = false;
	int64_t sum_err = 0;
	int64_t timeerror;
	int count = 0;

	if (ptp_type == -1) {
		ptp_type = SYNC;
		twoway = true;
	}

	PacketData *pkt;
	FOREACH_PKT_TYPE(s, ptp_type, pkt) {
		timeerror = tc_get_time_error(s, pkt, twoway, use_t4, measured_link_delay);
		if (timeerror > r.max || count == 0)
			r.max = timeerror;
		if (timeerror < r.min || count == 0)
			r.min = timeerror;
		sum_err += timeerror;
		count++;
	}
	r.mean = sum_err / count;
	return r;
}

static StatsResult stats_get_sync_latency(Stats *s)
{
	StatsResult r = { 0 };
	int64_t sum_latency = 0;
	PacketData *pkt;
	int64_t latency;
	int count = 0;

	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		latency = tc_get_latency(pkt);
		if (latency > r.max || count == 0)
			r.max = latency;
		if (latency < r.min || count == 0)
			r.min = latency;
		sum_latency += latency;
		count++;
	}
	r.mean = sum_latency / count;
	return r;
}

static int64_t pdv_get_lucky_packet(Stats *s)
{
	int64_t lucky_packet, tmp;
	PacketData *pkt;
	int count = 0;

	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		tmp = pkt->fst->rx_ts - tc_sync_get_tx_ts(pkt);
		if (tmp < lucky_packet || count == 0)
			lucky_packet = tmp;
		count++;
	}
	return lucky_packet;
}

StatsResult stats_get_sync_pdv(Stats *s)
{
	int64_t lucky_packet, tmp, sum = 0;
	StatsResult r = { 0 };
	PacketData *pkt;

	lucky_packet = pdv_get_lucky_packet(s);
	r.max = 0;
	r.min = 0;
	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		tmp = (pkt->fst->rx_ts - tc_sync_get_tx_ts(pkt)) - lucky_packet;
		sum += tmp;
		if (tmp > r.max)
			r.max = tmp;
	}
	r.mean = sum / s->count;
	return r;
}

void stats_show_te(Stats *s, char *p1, int count_left, bool measured_link_delay)
{
	StatsResult sync_time_error;
	StatsResult delay_time_error;
	StatsResult twoway_time_error;

	if (s->count == 0) {
		printf("No measurements\n");
		return;
	}

	if (count_left)
		printf("%d measurements (exited early, expected %d)\n", s->count,
		       s->count + count_left);
	else
		printf("%d measurements\n", s->count);

	printf("%s\n", p1);

	if (s->dm == DM_E2E) {
		sync_time_error = stats_get_time_error(s, SYNC, false, false);
		printf("--- T1 Time Error ---\n");
		printf("Mean: %" PRId64 "\n", sync_time_error.mean);
		printf("Max : %" PRId64 "\n", sync_time_error.max);
		printf("Min : %" PRId64 "\n", sync_time_error.min);
		delay_time_error = stats_get_time_error(s, DELAY_REQ, false, false);
		printf("--- T4 Time Error ---\n");
		printf("Mean: %" PRId64 "\n", delay_time_error.mean);
		printf("Max : %" PRId64 "\n", delay_time_error.max);
		printf("Min : %" PRId64 "\n", delay_time_error.min);
		/* 2way will not work like before since message
		 * association for was previously based on seqid
		 * matching up against time. Need to use ->current_delay.
		 * Passing 'true' should solve that.
		 */
		twoway_time_error = stats_get_time_error(s, -1, true, false);
		printf("--- 2WAY_TIME_ERROR ---\n");
		printf("Mean: %" PRId64 "\n", twoway_time_error.mean);
		printf("Max : %" PRId64 "\n", twoway_time_error.max);
		printf("Min : %" PRId64 "\n", twoway_time_error.min);
	} else {
		sync_time_error = stats_get_time_error(s, SYNC, false, measured_link_delay);
		if (measured_link_delay)
			printf("--- Time Error ---\n");
		else
			printf("--- Time Error ---\n");
		printf("Mean: %" PRId64 "\n", sync_time_error.mean);
		printf("Max : %" PRId64 "\n", sync_time_error.max);
		printf("Min : %" PRId64 "\n", sync_time_error.min);
		/* delay_time_error = stats_get_time_error(s, DELAY_REQ, measured_link_delay); */

		/* What should output look like for PDELAY? 
		 * Measured Link Delay
		 * How to calculate when not using measured_link_delay?
		 */
	}
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

	/* if (debugen) { */
	/* 	for (int i = 0; i < s->count; i++) { */
	/* 		print_tsinfo(&s->tsinfo[i]); */
	/* 	} */
	/* } */

	StatsResult sync_time_error = stats_get_time_error(s, SYNC, false, false);
	StatsResult delay_time_error = stats_get_time_error(s, DELAY_REQ, false, false);
	StatsResult twoway_time_error = stats_get_time_error(s, -1, false, false);
	StatsResult sync_latency = stats_get_sync_latency(s);
	StatsResult sync_pdv = stats_get_sync_pdv(s);

	printf("--- SYNC_TIME_ERROR ---\n");
	printf("Mean: %" PRId64 "\n", sync_time_error.mean);
	printf("Max : %" PRId64 "\n", sync_time_error.max);
	printf("Min : %" PRId64 "\n", sync_time_error.min);
	printf("--- DELAY_TIME_ERROR ---\n");
	printf("Mean: %" PRId64 "\n", delay_time_error.mean);
	printf("Max : %" PRId64 "\n", delay_time_error.max);
	printf("Min : %" PRId64 "\n", delay_time_error.min);
	printf("--- 2WAY_TIME_ERROR ---\n");
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

static int64_t get_tx_ts(PacketData *pkt)
{
	if (pkt->primary_type == SYNC)
		return tc_sync_get_tx_ts(pkt);
	else if (pkt->primary_type == DELAY_REQ)
		return pkt->fst->tx_ts;
	else if (pkt->primary_type == PDELAY_REQ)
		return pkt->fst->tx_ts;
	else
		ERR("%s: Bad packet type", __func__);
	return INT64_MIN;
}

static int64_t get_earliest_tx_ts(Stats *s)
{
	int64_t earliest = 0, tmp;

	for (int i = 0; i < s->count; i++) {
		tmp = get_tx_ts(&s->packets[i]);
		if (tmp < earliest || i == 0)
			earliest = tmp;
	}
	return earliest;
}

static void write_val_to_file(Stats *s, FILE *fp, PacketData *pkt, int64_t val, int64_t base_time)
{
	int64_t curr_time;
	curr_time = get_tx_ts(pkt) - base_time;
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

	base_time = get_earliest_tx_ts(s);

	fp = fopen(path, "w");
	if (!fp) {
		ERR("failed opening file %s: %m", path);
		return;
	}

	fprintf(fp, "SYNC_TIME_ERROR\n");
	PacketData *pkt;
	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		val = tc_get_time_error(s, pkt, false, false, false);
		write_val_to_file(s, fp, pkt, val, base_time);
	}
	fprintf(fp, "\n");
	fprintf(fp, "SYNC_LATENCY\n");
	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		val = tc_get_latency(pkt);
		write_val_to_file(s, fp, pkt, val, base_time);
	}
	fprintf(fp, "\n");
	fprintf(fp, "SYNC_PDV\n");
	lucky_packet = pdv_get_lucky_packet(s);
	FOREACH_PKT_TYPE(s, SYNC, pkt) {
		val = (pkt->fst->rx_ts - tc_sync_get_tx_ts(pkt)) - lucky_packet;
		write_val_to_file(s, fp, pkt, val, base_time);
	}
	fclose(fp);
}
