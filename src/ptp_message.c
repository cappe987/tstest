// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include "timestamping.h"
#include "tstest.h"

const char *ptp_default_clockid()
{
	return "\x00\x00\x00\xff\xfe\xaa\xaa\xaa";
}

struct ptp_header ptp_header_template()
{
	struct ptp_header hdr = { 0 };
	Octet dmac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	Octet smac[] = { 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa };

	ptp_set_dmac(&hdr, dmac);
	ptp_set_smac(&hdr, smac);
	memcpy(&hdr.ethertype, "\x88\xf7", 2);

	ptp_set_version(&hdr, 2);

	hdr.messageLength = htons(0x2c);
	hdr.domainNumber = 0x00;
	hdr.flagField[0] = 0x02;
	memcpy(&hdr.sourcePortIdentity.clockIdentity.id, ptp_default_clockid(), 6);
	hdr.sourcePortIdentity.portNumber = htons(0x1);
	ptp_set_seqId(&hdr, 0);

	return hdr;
}

struct sync_msg create_sync(struct ptp_header hdr)
{
	struct sync_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct delay_req_msg create_delay_req(struct ptp_header hdr)
{
	struct delay_req_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct pdelay_req_msg create_pdelay_req(struct ptp_header hdr)
{
	struct pdelay_req_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct pdelay_resp_msg create_pdelay_resp(struct ptp_header hdr)
{
	struct pdelay_resp_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct follow_up_msg create_follow_up(struct ptp_header hdr)
{
	struct follow_up_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct delay_resp_msg create_delay_resp(struct ptp_header hdr)
{
	struct delay_resp_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct pdelay_resp_fup_msg create_pdelay_resp_fup(struct ptp_header hdr)
{
	struct pdelay_resp_fup_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct announce_msg create_announce(struct ptp_header hdr)
{
	struct announce_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct signaling_msg create_signaling(struct ptp_header hdr)
{
	struct signaling_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

struct management_msg create_management(struct ptp_header hdr)
{
	struct management_msg msg = { 0 };
	msg.hdr = hdr;
	return msg;
}

int str2ptp_type(const char *str)
{
	if (strcmp(str, "sync") == 0)
		return SYNC;
	else if (strcmp(str, "delay_req") == 0)
		return DELAY_REQ;
	else if (strcmp(str, "pdelay_req") == 0)
		return PDELAY_REQ;
	else if (strcmp(str, "pdelay_resp") == 0)
		return PDELAY_RESP;
	else if (strcmp(str, "follow_up") == 0)
		return FOLLOW_UP;
	else if (strcmp(str, "delay_resp") == 0)
		return DELAY_RESP;
	else if (strcmp(str, "pdelay_resp_fup") == 0)
		return PDELAY_RESP_FUP;
	else if (strcmp(str, "announce") == 0)
		return ANNOUNCE;
	else if (strcmp(str, "signaling") == 0)
		return SIGNALING;
	else if (strcmp(str, "management") == 0)
		return MANAGEMENT;
	else
		return -1;
}

char *ptp_type2str(int type)
{
	switch (type) {
	case SYNC:
		return "sync";
	case DELAY_REQ:
		return "delay_req";
	case FOLLOW_UP:
		return "follow_up";
	case DELAY_RESP:
		return "delay_resp";
	case MANAGEMENT:
		return "management";
	case PDELAY_REQ:
		return "pdelay_req";
	case PDELAY_RESP:
		return "pdelay_resp";
	case PDELAY_RESP_FUP:
		return "pdelay_resp_fup";
	case ANNOUNCE:
		return "announce";
	case SIGNALING:
		return "signaling";
	default:
		return "INVALID";
	}
}

int ptp_type2controlField(int type)
{
	switch (type) {
	case SYNC:
		return 0x0;
	case DELAY_REQ:
		return 0x1;
	case FOLLOW_UP:
		return 0x2;
	case DELAY_RESP:
		return 0x3;
	case MANAGEMENT:
		return 0x4;
	case PDELAY_REQ:
	case PDELAY_RESP:
	case PDELAY_RESP_FUP:
	case ANNOUNCE:
	case SIGNALING:
		return 0x5;
	default:
		return -1;
	}
}

int ptp_msg_get_size(int type)
{
	switch (type) {
	case SYNC:
		return sizeof(struct sync_msg);
	case DELAY_REQ:
		return sizeof(struct delay_req_msg);
	case FOLLOW_UP:
		return sizeof(struct follow_up_msg);
	case DELAY_RESP:
		return sizeof(struct delay_resp_msg);
	case MANAGEMENT:
		return sizeof(struct management_msg);
	case PDELAY_REQ:
		return sizeof(struct pdelay_req_msg);
	case PDELAY_RESP:
		return sizeof(struct pdelay_resp_msg);
	case PDELAY_RESP_FUP:
		return sizeof(struct pdelay_resp_fup_msg);
	case ANNOUNCE:
		return sizeof(struct announce_msg);
	case SIGNALING:
		return sizeof(struct signaling_msg);
	default:
		return -1;
	}
}

union Message ptp_msg_create_type(struct ptp_header hdr, Octet type)
{
	union Message msg;

	switch (type) {
	case SYNC:
		msg.sync = create_sync(hdr);
		break;
	case DELAY_REQ:
		msg.delay_req = create_delay_req(hdr);
		break;
	case FOLLOW_UP:
		msg.follow_up = create_follow_up(hdr);
		break;
	case DELAY_RESP:
		msg.delay_resp = create_delay_resp(hdr);
		break;
	case MANAGEMENT:
		msg.management = create_management(hdr);
		break;
	case PDELAY_REQ:
		msg.pdelay_req = create_pdelay_req(hdr);
		break;
	case PDELAY_RESP:
		msg.pdelay_resp = create_pdelay_resp(hdr);
		break;
	case PDELAY_RESP_FUP:
		msg.pdelay_resp_fup = create_pdelay_resp_fup(hdr);
		break;
	case ANNOUNCE:
		msg.announce = create_announce(hdr);
		break;
	case SIGNALING:
		msg.signaling = create_signaling(hdr);
		break;
	}
	return msg;
}

struct Timestamp ns_to_be_timestamp(Integer64 ns)
{
	struct Timestamp ts;

	Integer64 sec = ns / NS_PER_SEC;
	Integer64 nsec = ns % NS_PER_SEC;
	ts.seconds_lsb = htobe32(sec & 0xFFFFFFFF);
	ts.seconds_msb = htobe16((sec >> 32) & 0xFFFF);
	ts.nanoseconds = htobe32(nsec);

	return ts;
}

Integer64 be_timestamp_to_ns(struct Timestamp ts)
{
	Integer64 sec = ((Integer64)be16toh(ts.seconds_msb) << 32) + be32toh(ts.seconds_lsb);
	Integer64 nsec = be32toh(ts.nanoseconds);

	return sec * NS_PER_SEC + nsec;
}
