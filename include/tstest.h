// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>


#ifndef __TS_TEST_H__
#define __TS_TEST_H__

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>


typedef	int       Boolean;
typedef uint8_t   Enumeration8;
typedef uint16_t  Enumeration16;
typedef int8_t    Integer8;
typedef uint8_t   UInteger8;
typedef int16_t   Integer16;
typedef uint16_t  UInteger16;
typedef int32_t   Integer32;
typedef uint32_t  UInteger32;
typedef int64_t   Integer64;
typedef uint8_t   Octet;


/* Values for the messageType field */
#define SYNC                  0x0
#define DELAY_REQ             0x1
#define PDELAY_REQ            0x2
#define PDELAY_RESP           0x3
#define FOLLOW_UP             0x8
#define DELAY_RESP            0x9
#define PDELAY_RESP_FOLLOW_UP 0xA
#define ANNOUNCE              0xB
#define SIGNALING             0xC
#define MANAGEMENT            0xD

#define PACKED __attribute__((packed))

typedef Integer64 TimeInterval; /* nanoseconds << 16 */

/** On the wire time stamp format. */
struct Timestamp {
	uint16_t   seconds_msb; /* 16 bits + */
	uint32_t   seconds_lsb; /* 32 bits = 48 bits*/
	UInteger32 nanoseconds;
} PACKED;

/** Internal binary time stamp format. */
struct timestamp {
	uint64_t   sec;
	UInteger32 nsec;
};

struct ClockIdentity {
	Octet id[8];
};

struct PortIdentity {
	struct ClockIdentity clockIdentity;
	UInteger16           portNumber;
} PACKED;

struct PortAddress {
	Enumeration16 networkProtocol;
	UInteger16    addressLength;
	Octet         address[0];
} PACKED;

struct PhysicalAddress {
	UInteger16 length;
	Octet      address[0];
} PACKED;

struct ClockQuality {
	UInteger8     clockClass;
	Enumeration8  clockAccuracy;
	UInteger16    offsetScaledLogVariance;
} PACKED;

struct TLV {
	Enumeration16 type;
	UInteger16    length; /* must be even */
	Octet         value[0];
} PACKED;

struct PTPText {
	UInteger8 length;
	Octet     text[0];
} PACKED;



struct ptp_header {
	Octet               dmac[6];
	Octet               smac[6];
	UInteger16          ethertype;
	uint8_t             tsmt; /* transportSpecific | messageType */
	uint8_t             ver;  /* reserved          | versionPTP  */
	UInteger16          messageLength;
	UInteger8           domainNumber;
	Octet               reserved1;
	Octet               flagField[2];
	Integer64           correction;
	UInteger32          reserved2;
	//struct PortIdentity sourcePortIdentity;
	Octet               clockIdentity[8];
	UInteger16          sourcePort;
	UInteger16          sequenceId;
	UInteger8           control;
	Integer8            logMessageInterval;
} PACKED;

struct announce_msg {
	struct ptp_header    hdr;
	struct Timestamp     originTimestamp;
	Integer16            currentUtcOffset;
	Octet                reserved;
	UInteger8            grandmasterPriority1;
	struct ClockQuality  grandmasterClockQuality;
	UInteger8            grandmasterPriority2;
	struct ClockIdentity grandmasterIdentity;
	UInteger16           stepsRemoved;
	Enumeration8         timeSource;
	uint8_t              suffix[0];
} PACKED;

struct sync_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
} PACKED;

struct delay_req_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
	uint8_t             suffix[0];
} PACKED;

struct follow_up_msg {
	struct ptp_header   hdr;
	struct Timestamp    preciseOriginTimestamp;
	uint8_t             suffix[0];
} PACKED;

struct delay_resp_msg {
	struct ptp_header   hdr;
	struct Timestamp    receiveTimestamp;
	struct PortIdentity requestingPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct pdelay_req_msg {
	struct ptp_header   hdr;
	struct Timestamp    originTimestamp;
	struct PortIdentity reserved;
} PACKED;

struct pdelay_resp_msg {
	struct ptp_header   hdr;
	struct Timestamp    requestReceiptTimestamp;
	struct PortIdentity requestingPortIdentity;
} PACKED;

struct pdelay_resp_fup_msg {
	struct ptp_header   hdr;
	struct Timestamp    responseOriginTimestamp;
	struct PortIdentity requestingPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct signaling_msg {
	struct ptp_header   hdr;
	struct PortIdentity targetPortIdentity;
	uint8_t             suffix[0];
} PACKED;

struct management_msg {
	struct ptp_header   hdr;
	struct PortIdentity targetPortIdentity;
	UInteger8           startingBoundaryHops;
	UInteger8           boundaryHops;
	uint8_t             flags; /* reserved | actionField */
	uint8_t             reserved;
	uint8_t             suffix[0];
} PACKED;

union Message {
	struct sync_msg            sync;
	struct announce_msg        announce;
	struct delay_req_msg       delay_req;
	struct follow_up_msg       follow_up;
	struct delay_resp_msg      delay_resp;
	struct pdelay_req_msg      pdelay_req;
	struct pdelay_resp_msg     pdelay_resp;
	struct pdelay_resp_fup_msg pdelay_resp_fup;
	struct signaling_msg       signaling;
	struct management_msg      management;
} PACKED;

/* pkt.c */
int run_pkt_mode(int argc, char **argv);

/* extts.c */
int run_extts_mode(int argc, char **argv);

/* ptp_message.c */
int str2ptp_type(const char *str);
int ptp_type2controlField(int type);
struct ptp_header ptp_header_template();
int ptp_msg_get_size(int type);
struct sync_msg create_sync(struct ptp_header hdr);
union Message ptp_msg_create_type(struct ptp_header hdr, Octet type);

static void ptp_set_dmac(struct ptp_header *hdr, Octet dmac[ETH_ALEN]) {
	memcpy(hdr->dmac, dmac, ETH_ALEN);
}

static void ptp_set_smac(struct ptp_header *hdr, Octet smac[ETH_ALEN]) {
	memcpy(hdr->smac, smac, ETH_ALEN);
}

static void ptp_set_type(struct ptp_header *hdr, Octet type) {
	hdr->tsmt = 0xF & type;
	hdr->control = ptp_type2controlField(type);
}

static void ptp_set_version(struct ptp_header *hdr, Octet version) {
	hdr->ver = 0xF & version;
}

static void ptp_set_srcport(struct ptp_header *hdr, Octet srcport) {
	hdr->sourcePort = srcport;
}

static void ptp_set_seqId(struct ptp_header *hdr, UInteger16 seq) {
	hdr->sequenceId = htons(seq);
}

#endif /* __TS_TEST_H__ */
