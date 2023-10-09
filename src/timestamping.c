// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2012 Richard Cochran <richardcochran@gmail.com>
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>

#include <asm/types.h>

#include <linux/if_ether.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include <poll.h>

#include "tstest.h"
#include "liblink.h"
#include "timestamping.h"

#define NS_PER_SEC 1000000000

#ifndef CLOCK_TAI
#define CLOCK_TAI                       11
#endif

#ifndef SCM_TXTIME
#define SO_TXTIME               61
#define SCM_TXTIME              SO_TXTIME
#endif

/* ptp4l --tx_timestamp_timeout */
int sk_tx_timeout = 1000;
enum hwts_filter_mode sk_hwts_filter_mode = HWTS_FILTER_NORMAL;

/* FIXME: get rid of these global variables */
int ptp_type;
union Message message;
int txcount = 0;
int txcount_flag = 0;
int nonstop_flag = 0;
int rx_only = 0;
int tx_only = 0;
int debugen = 0;

static uint64_t gettime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_TAI, &ts))
		printf("error gettime");

	return ts.tv_sec * (1000ULL * 1000 * 1000) + ts.tv_nsec;
}

static int do_send_one(int fdt, int length)
{
	char control[CMSG_SPACE(sizeof(uint64_t))];
	struct msghdr msg = {0};
	struct iovec iov = {0};
	struct cmsghdr *cm;
	uint64_t tdeliver;
	int ret;
	char *buf;

	buf = (char *)malloc(length);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, &message, ptp_msg_get_size(ptp_type));

	iov.iov_base = buf;
	iov.iov_len = length;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*if (delay_us >= 0) {*/
		/*memset(control, 0, sizeof(control));*/
		/*msg.msg_control = &control;*/
		/*msg.msg_controllen = sizeof(control);*/

		/*tdeliver = gettime_ns() + delay_us * 1000;*/
		/*DEBUG("set TXTIME is %ld\n", tdeliver);*/
		/*cm = CMSG_FIRSTHDR(&msg);*/
		/*cm->cmsg_level = SOL_SOCKET;*/
		/*cm->cmsg_type = SCM_TXTIME;*/
		/*cm->cmsg_len = CMSG_LEN(sizeof(tdeliver));*/
		/*memcpy(CMSG_DATA(cm), &tdeliver, sizeof(tdeliver));*/
	/*}*/

	ret = sendmsg(fdt, &msg, 0);
	if (ret == -1)
		printf("error write, return error sendmsg!\n");
	if (ret == 0)
		printf("error write: 0B");

	free(buf);
	return ret;
}

void sendpacket(int sock, unsigned char *mac)
{
	struct timeval now, nowb;
	int res;
	/*int i;*/

	/*for (i = 0; i < MAC_LEN; i++)*/
		/*sync_packet[6 + i] = mac[i];*/
	/*sync_packet[17] = length >> 8;*/
	/*sync_packet[18] = (char)(length & 0x00ff);*/

	gettimeofday(&nowb, 0);

	/*if (length < sizeof(sync_packet))*/
		/*res = send(sock, sync_packet, sizeof(sync_packet), 0);*/
	/*else {*/
#if 0
		char *buf = (char *)malloc(length);

		memcpy(buf, sync_packet, sizeof(sync_packet));
		res = send(sock, buf, length, 0);
		free(buf);
#endif
	res = do_send_one(sock, ptp_msg_get_size(ptp_type));
	/*}*/

	gettimeofday(&now, 0);
	if (res < 0) {
		DEBUG("%s: %s\n", "send", strerror(errno));
	} else {
		if (debugen)
			DEBUG("%ld.%06ld - %ld.%06ld: sent %d bytes\n",
			      (long)nowb.tv_sec, (long)nowb.tv_usec,
			      (long)now.tv_sec, (long)now.tv_usec,
			      res);
		else
			printf("Sent %d bytes\n", res);
	}
}

static void printpacket(struct msghdr *msg, int res,
			int recvmsg_flags)
{
	struct sockaddr_in *from_addr = (struct sockaddr_in *)msg->msg_name;
	struct cmsghdr *cmsg;
	struct timeval now;

	if (debugen) {
		gettimeofday(&now, 0);
		DEBUG("%ld.%06ld: received %s data, %d bytes from %s, %zu bytes control messages\n",
		       (long)now.tv_sec, (long)now.tv_usec,
		       (recvmsg_flags & MSG_ERRQUEUE) ? "error" : "regular",
		       res,
		       inet_ntoa(from_addr->sin_addr),
		       msg->msg_controllen);
	}

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		DEBUG("   cmsg len %zu: ", cmsg->cmsg_len);
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			DEBUG("SOL_SOCKET ");
			switch (cmsg->cmsg_type) {
			case SO_TIMESTAMP: {
				struct timeval *stamp =
					(struct timeval *)CMSG_DATA(cmsg);
				DEBUG("SO_TIMESTAMP %ld.%06ld",
				       (long)stamp->tv_sec,
				       (long)stamp->tv_usec);
				break;
			}
			case SO_TIMESTAMPNS: {
				struct timespec *stamp =
					(struct timespec *)CMSG_DATA(cmsg);
				DEBUG("SO_TIMESTAMPNS %ld.%09ld",
				       (long)stamp->tv_sec,
				       (long)stamp->tv_nsec);
				break;
			}
			case SO_TIMESTAMPING: {
				struct timespec *stamp =
					(struct timespec *)CMSG_DATA(cmsg);
				DEBUG("SO_TIMESTAMPING ");
				stamp++;
				/* skip deprecated HW transformed */
				stamp++;
				printf("  HW raw %ld.%09ld\n",
				       (long)stamp->tv_sec,
				       (long)stamp->tv_nsec);
				if (recvmsg_flags & MSG_ERRQUEUE) {
					/*if (!fully_send) {*/
					txcount_flag = 1;
					if (nonstop_flag) {
						txcount++;
					} else {
						txcount--;
					}
					/*} else {*/
						/*if (nonstop_flag) {*/
							/*txcount++;*/
						/*} else {*/
							/*txcount--;*/
							/*if (!txcount)*/
								/*txcount_flag = 1;*/
						/*}*/
					/*}*/
					DEBUG("tx counter %d\n", txcount);
				}
				break;
			}
			default:
				DEBUG("type %d", cmsg->cmsg_type);
				break;
			}
			break;
		case IPPROTO_IP:
			DEBUG("IPPROTO_IP ");
			switch (cmsg->cmsg_type) {
			case IP_RECVERR: {
				struct sock_extended_err *err =
					(struct sock_extended_err *)CMSG_DATA(cmsg);
				DEBUG("IP_RECVERR ee_errno '%s' ee_origin %d => %s",
					strerror(err->ee_errno),
					err->ee_origin,
#ifdef SO_EE_ORIGIN_TIMESTAMPING
					err->ee_origin == SO_EE_ORIGIN_TIMESTAMPING ?
					"bounced packet" : "unexpected origin"
#else
					"probably SO_EE_ORIGIN_TIMESTAMPING"
#endif
					);
				break;
			}
			case IP_PKTINFO: {
				struct in_pktinfo *pktinfo =
					(struct in_pktinfo *)CMSG_DATA(cmsg);
				DEBUG("IP_PKTINFO interface index %u",
					pktinfo->ipi_ifindex);
				break;
			}
			default:
				DEBUG("type %d", cmsg->cmsg_type);
				break;
			}
			break;
		default:
			DEBUG("level %d type %d",
				cmsg->cmsg_level,
				cmsg->cmsg_type);
			break;
		}
		DEBUG("\n");
	}
}

static void recvpacket(int sock, int recvmsg_flags)
{
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	int res;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	res = recvmsg(sock, &msg, recvmsg_flags | MSG_DONTWAIT);
	if (res < 0)
		DEBUG("%s %s: %s\n",
		       "recvmsg",
		       "regular",
		       strerror(errno));
	else
		printpacket(&msg, res, recvmsg_flags);
}

void rcv_pkt(int sock)
{
	int res;
	fd_set readfs, errorfs;

	while (!txcount_flag) {
		FD_ZERO(&readfs);
		FD_ZERO(&errorfs);
		FD_SET(sock, &readfs);
		FD_SET(sock, &errorfs);

		res = select(sock + 1, &readfs, 0, &errorfs, NULL);
		if (res > 0) {
			recvpacket(sock, 0);
			if (!rx_only)
				recvpacket(sock, MSG_ERRQUEUE);
		}
	}
}

void setsockopt_txtime(int fd)
{
	struct sock_txtime so_txtime_val = {
			.clockid =  CLOCK_TAI,
			/*.flags = SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS */
			.flags = SOF_TXTIME_REPORT_ERRORS
			};
	struct sock_txtime so_txtime_val_read = { 0 };
	socklen_t vallen = sizeof(so_txtime_val);

	/*if (send_now)*/
		/*so_txtime_val.flags |= SOF_TXTIME_DEADLINE_MODE;*/

	if (setsockopt(fd, SOL_SOCKET, SO_TXTIME,
		       &so_txtime_val, sizeof(so_txtime_val)))
		printf("setsockopt txtime error!\n");

	if (getsockopt(fd, SOL_SOCKET, SO_TXTIME,
		       &so_txtime_val_read, &vallen))
		printf("getsockopt txtime error!\n");

	if (vallen != sizeof(so_txtime_val) ||
	    memcmp(&so_txtime_val, &so_txtime_val_read, vallen))
		printf("getsockopt txtime: mismatch\n");
}




/* ------- Imported from Linuxptp -------------- */



static inline tmv_t timespec_to_tmv(struct timespec ts)
{
	tmv_t t;
	t.ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
	return t;
}

static void init_ifreq(struct ifreq *ifreq, struct hwtstamp_config *cfg,
	const char *device)
{
	memset(ifreq, 0, sizeof(*ifreq));
	memset(cfg, 0, sizeof(*cfg));

	strncpy(ifreq->ifr_name, device, sizeof(ifreq->ifr_name) - 1);

	ifreq->ifr_data = (void *) cfg;
}

static int hwts_init(int fd, const char *device, int rx_filter,
		     int rx_filter2, int tx_type)
{
	struct ifreq ifreq;
	struct hwtstamp_config cfg;
	int orig_rx_filter;
	int err;

	init_ifreq(&ifreq, &cfg, device);

	/* Test if VLAN over bond is supported. */
	cfg.flags = HWTSTAMP_FLAG_BONDED_PHC_INDEX;
	err = ioctl(fd, SIOCGHWTSTAMP, &ifreq);
	if (err < 0) {
		/*
		 * Fall back without flag if user runs new build on old kernel
		 * or if driver does not support SIOCGHWTSTAMP ioctl.
		 */
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			init_ifreq(&ifreq, &cfg, device);
		} else {
			ERR("ioctl SIOCGHWTSTAMP failed: %m");
			return err;
		}
	}

	switch (sk_hwts_filter_mode) {
	case HWTS_FILTER_CHECK:
		err = ioctl(fd, SIOCGHWTSTAMP, &ifreq);
		if (err < 0) {
			ERR("ioctl SIOCGHWTSTAMP failed: %m");
			return err;
		}
		break;
	case HWTS_FILTER_FULL:
		cfg.tx_type   = tx_type;
		cfg.rx_filter = HWTSTAMP_FILTER_ALL;
		err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
		if (err < 0) {
			ERR("ioctl SIOCSHWTSTAMP failed: %m");
			return err;
		}
		break;
	case HWTS_FILTER_NORMAL:
		cfg.tx_type   = tx_type;
		cfg.rx_filter = orig_rx_filter = rx_filter;
		err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
		if (err < 0) {
			printf("warning: driver rejected most general HWTSTAMP filter");

			init_ifreq(&ifreq, &cfg, device);
			cfg.tx_type   = tx_type;
			cfg.rx_filter = orig_rx_filter = rx_filter2;

			err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
			if (err < 0) {
				ERR("ioctl SIOCSHWTSTAMP failed: %m");
				return err;
			}
		}
		if (cfg.rx_filter == HWTSTAMP_FILTER_SOME)
			cfg.rx_filter = orig_rx_filter;
		break;
	}

	if (cfg.tx_type != tx_type ||
	    (cfg.rx_filter != rx_filter &&
	     cfg.rx_filter != rx_filter2 &&
	     cfg.rx_filter != HWTSTAMP_FILTER_ALL)) {
		DEBUG("tx_type   %d not %d", cfg.tx_type, tx_type);
		DEBUG("rx_filter %d not %d or %d", cfg.rx_filter, rx_filter,
			 rx_filter2);
		ERR("The current filter does not match the required");
		return -1;
	}

	return 0;
}

static short sk_events = POLLPRI;
static short sk_revents = POLLPRI;

int sk_receive(int fd, void *buf, int buflen,
	       struct address *addr, struct hw_timestamp *hwts, int flags)
{
	char control[256];
	int cnt = 0, res = 0, level, type;
	struct cmsghdr *cm;
	struct iovec iov = { buf, buflen };
	struct msghdr msg;
	struct timespec *sw, *ts = NULL;

	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	if (addr) {
		msg.msg_name = &addr->ss;
		msg.msg_namelen = sizeof(addr->ss);
	}
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (flags == MSG_ERRQUEUE) {
		struct pollfd pfd = { fd, sk_events, 0 };
		res = poll(&pfd, 1, sk_tx_timeout);
		/* Retry once on EINTR to avoid logging errors before exit */
		if (res < 0 && errno == EINTR)
			res = poll(&pfd, 1, sk_tx_timeout);
		if (res < 1) {
			ERR("%s", res ? "poll for tx timestamp failed: %m" :
			             "timed out while polling for tx timestamp");
			ERR("increasing tx_timestamp_timeout may correct "
			       "this issue, but it is likely caused by a driver bug");
			return -errno;
		} else if (!(pfd.revents & sk_revents)) {
			ERR("poll for tx timestamp woke up on non ERR event");
			return -1;
		}
	}

	cnt = recvmsg(fd, &msg, flags);
	if (cnt < 0) {
		ERR("recvmsg%sfailed: %m",
		       flags == MSG_ERRQUEUE ? " tx timestamp " : " ");
	}
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		level = cm->cmsg_level;
		type  = cm->cmsg_type;
		if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
			if (cm->cmsg_len < sizeof(*ts) * 3) {
				printf("warning: short SO_TIMESTAMPING message");
				return -EMSGSIZE;
			}
			ts = (struct timespec *) CMSG_DATA(cm);
		}
		if (SOL_SOCKET == level && SO_TIMESTAMPNS == type) {
			if (cm->cmsg_len < sizeof(*sw)) {
				printf("warning: short SO_TIMESTAMPNS message");
				return -EMSGSIZE;
			}
			sw = (struct timespec *) CMSG_DATA(cm);
			hwts->sw = timespec_to_tmv(*sw);
		}
	}

	if (addr)
		addr->len = msg.msg_namelen;

	if (!ts) {
		memset(&hwts->ts, 0, sizeof(hwts->ts));
		return cnt < 0 ? -errno : cnt;
	}

	switch (hwts->type) {
	case TS_SOFTWARE:
		hwts->ts = timespec_to_tmv(ts[0]);
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		hwts->ts = timespec_to_tmv(ts[2]);
		break;
	case TS_LEGACY_HW:
		hwts->ts = timespec_to_tmv(ts[1]);
		break;
	}
	return cnt < 0 ? -errno : cnt;
}

static int raw_send(struct transport *t, struct fdarray *fda,
		    enum transport_event event, int peer, void *buf, int len,
		    struct address *addr, struct hw_timestamp *hwts)
{
	struct raw *raw = container_of(t, struct raw, t);
	ssize_t cnt;
	unsigned char pkt[1600]; //, *ptr = buf;
	struct eth_hdr *hdr;
	struct tagged_frame_header *tag_hdr;
	int fd = -1;

	switch (event) {
	case TRANS_GENERAL:
		fd = fda->fd[FD_GENERAL];
		break;
	case TRANS_EVENT:
	case TRANS_ONESTEP:
	case TRANS_P2P1STEP:
	case TRANS_DEFER_EVENT:
		fd = fda->fd[FD_EVENT];
		break;
	}

	if (!addr)
		addr = peer ? &raw->p2p_addr : &raw->ptp_addr;

	/* To send frames with 802.1Q tag. */
	/*if (raw->egress_vlan_tagged) {*/
		/*ptr -= sizeof(*tag_hdr);*/
		/*len += sizeof(*tag_hdr);*/
		/*tag_hdr = (struct tagged_frame_header *) ptr;*/
		/*addr_to_mac(&tag_hdr->ether_header.ether_dhost, addr);*/
		/*addr_to_mac(&tag_hdr->ether_header.ether_shost, &raw->src_addr);*/
		/*tag_hdr->ether_header.ether_type = htons(ETH_P_8021Q);*/
		/*tag_hdr->vlan_tags = htons((raw->egress_vlan_prio << 13) | raw->egress_vlan_id);*/
		/*tag_hdr->enc_ethertype = htons(ETH_P_1588);*/
	/*} else {*/
		/*ptr -= sizeof(*hdr);*/
		/*len += sizeof(*hdr);*/
		/*hdr = (struct eth_hdr *) ptr;*/
		/*addr_to_mac(&hdr->dst, addr);*/
		/*addr_to_mac(&hdr->src, &raw->src_addr);*/
		/*hdr->type = htons(ETH_P_1588);*/
	/*}*/

	cnt = send(fd, buf, len, 0);
	if (cnt < 1) {
		return -errno;
	}
	/*
	 * Get the time stamp right away.
	 */
	return event == TRANS_EVENT ? sk_receive(fd, pkt, len, NULL, hwts, MSG_ERRQUEUE) : cnt;
}

int sk_timestamping_init(int fd, const char *device, enum timestamp_type type,
			 enum transport_type transport, int vclock)
{
	int err, filter1, filter2 = 0, flags, tx_type = HWTSTAMP_TX_ON;
	struct so_timestamping timestamping;

	switch (type) {
	case TS_SOFTWARE:
		flags = SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		break;
	case TS_LEGACY_HW:
		flags = SOF_TIMESTAMPING_TX_HARDWARE |
			SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_SYS_HARDWARE;
		break;
	default:
		return -1;
	}

	filter1 = HWTSTAMP_FILTER_PTP_V2_EVENT;
	switch (type) {
	case TS_SOFTWARE:
		tx_type = HWTSTAMP_TX_OFF;
		break;
	case TS_HARDWARE:
	case TS_LEGACY_HW:
		tx_type = HWTSTAMP_TX_ON;
		break;
	case TS_ONESTEP:
		tx_type = HWTSTAMP_TX_ONESTEP_SYNC;
		break;
	case TS_P2P1STEP:
		tx_type = HWTSTAMP_TX_ONESTEP_P2P;
		break;
	}
	switch (transport) {
	case TRANS_UDP_IPV4:
	case TRANS_UDP_IPV6:
		filter2 = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
		break;
	case TRANS_IEEE_802_3:
		filter2 = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
		break;
	case TRANS_DEVICENET:
	case TRANS_CONTROLNET:
	case TRANS_PROFINET:
	case TRANS_UDS:
		return -1;
	}

	err = hwts_init(fd, device, filter1, filter2, tx_type);
	if (err && !(type == TS_SOFTWARE && errno == ENOTSUP))
		return err;

	if (vclock >= 0)
		flags |= SOF_TIMESTAMPING_BIND_PHC;

	timestamping.flags = flags;
	timestamping.bind_phc = vclock;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
		       &timestamping, sizeof(timestamping)) < 0) {
		ERR("ioctl SO_TIMESTAMPING failed: %m");
		return -1;
	}

	flags = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
		       &flags, sizeof(flags)) < 0) {
		printf("warning: %s: SO_SELECT_ERR_QUEUE: %m", device);
		sk_events = 0;
		sk_revents = POLLERR;
	}

	/* Enable the sk_check_fupsync option, perhaps. */
	/*if (sk_general_init(fd)) {*/
		/*return -1;*/
	/*}*/

	return 0;
}



