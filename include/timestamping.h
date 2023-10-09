// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2012 Richard Cochran <richardcochran@gmail.com>
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef __TSTEST_TIMESTAMPING_H__
#define __TSTEST_TIMESTAMPING_H__

#include <time.h>
#include <inttypes.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/in.h>

/* A lot taken from Linuxptp project */

#define NS_PER_SEC 1000000000

/**
 * We implement the time value as a 64 bit signed integer containing
 * nanoseconds. Using this representation, we could really spare the
 * arithmetic functions such as @ref tmv_add() and the like, and just
 * use plain old math operators in the code.
 *
 * However, we are going to be a bit pedantic here and enforce the
 * use of the these functions, so that we can easily upgrade the code
 * to a finer representation later on. In that way, we can make use of
 * the fractional nanosecond parts of the correction fields, if and
 * when people start asking for them.
 */
typedef struct {
	int64_t ns;
} tmv_t;

#ifndef HWTSTAMP_FLAG_BONDED_PHC_INDEX
enum {
	HWTSTAMP_FLAG_BONDED_PHC_INDEX = (1<<0),
};
#endif

/* Defines the available Hardware time-stamp setting modes. */
enum hwts_filter_mode {
	HWTS_FILTER_NORMAL,    /* set hardware filters in normal way */
	HWTS_FILTER_CHECK,     /* check filters but do not change them */
	HWTS_FILTER_FULL,      /* Use time-stamp on all received packets */
};

/* Values from networkProtocol enumeration 7.4.1 Table 3 */
enum transport_type {
	/* 0 is Reserved in spec. Use it for UDS */
	TRANS_UDS = 0,
	TRANS_UDP_IPV4 = 1,
	TRANS_UDP_IPV6,
	TRANS_IEEE_802_3,
	TRANS_DEVICENET,
	TRANS_CONTROLNET,
	TRANS_PROFINET,
};

/**
 * Values for the 'event' parameter in transport_send() and
 * transport_peer().
 */
enum transport_event {
	TRANS_GENERAL,
	TRANS_EVENT,
	TRANS_ONESTEP,
	TRANS_P2P1STEP,
	TRANS_DEFER_EVENT,
};

enum timestamp_type {
	TS_SOFTWARE,
	TS_HARDWARE,
	TS_LEGACY_HW,
	TS_ONESTEP,
	TS_P2P1STEP,
};

struct hw_timestamp {
	enum timestamp_type type;
	tmv_t ts;
	tmv_t sw;
};

struct address {
	socklen_t len;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_ll sll;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
		struct sockaddr sa;
	};
};


int sk_receive(int fd, void *buf, int buflen,
	       struct address *addr, struct hw_timestamp *hwts, int flags);
int raw_send(int fd, enum transport_event event, void *buf, int len,
	     struct hw_timestamp *hwts);
int sk_timestamping_init(int fd, const char *device, enum timestamp_type type,
			 enum transport_type transport, int vclock);
//int socket_init_raw(char *interface);
int open_socket(const char *name, int event, unsigned char *ptp_dst_mac,
		unsigned char *p2p_dst_mac, int socket_priority);

#endif /* __TSTEST_TIMESTAMPING_H__ */