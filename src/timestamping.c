// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2012 Richard Cochran <richardcochran@gmail.com>
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <linux/sockios.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

#include "net_tstamp_cpy.h"
#include "timestamping.h"
#include "liblink.h"
#include "tstest.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef CLOCK_TAI
#define CLOCK_TAI 11
#endif

#ifndef SCM_TXTIME
#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME
#endif

/* ptp4l --tx_timestamp_timeout */
/* int sk_tx_timeout = 1000; */
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

/* ------- Imported from Linuxptp and modified -------------- */

static inline tmv_t timespec_to_tmv(struct timespec ts)
{
	tmv_t t;
	t.ns = (int64_t)ts.tv_sec * NS_PER_SEC + (int64_t)ts.tv_nsec;
	return t;
}

static void init_ifreq(struct ifreq *ifreq, struct hwtstamp_config *cfg, const char *device)
{
	memset(ifreq, 0, sizeof(*ifreq));
	memset(cfg, 0, sizeof(*cfg));

	strncpy(ifreq->ifr_name, device, sizeof(ifreq->ifr_name) - 1);

	ifreq->ifr_data = (void *)cfg;
}

static int hwts_init(int fd, const char *device, int rx_filter, int rx_filter2, int clk_type,
		     int tx_type, int domain, int delay_mechanism, int header_offset)
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
		cfg.tx_type = tx_type;
		cfg.rx_filter = HWTSTAMP_FILTER_ALL;
		cfg.clk_type = clk_type;
		cfg.domain = domain;
		cfg.delay_mechanism = delay_mechanism;
		cfg.header_offset = header_offset;
		err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
		if (err < 0) {
			ERR("ioctl SIOCSHWTSTAMP failed: %m");
			return err;
		}
		break;
	case HWTS_FILTER_NORMAL:
		cfg.tx_type = tx_type;
		cfg.rx_filter = orig_rx_filter = rx_filter;
		cfg.clk_type = clk_type;
		cfg.domain = domain;
		cfg.delay_mechanism = delay_mechanism;
		cfg.header_offset = header_offset;
		err = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
		if (err < 0) {
			printf("warning: driver rejected most general HWTSTAMP filter\n");

			init_ifreq(&ifreq, &cfg, device);
			cfg.tx_type = tx_type;
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

	if (cfg.tx_type != tx_type || (cfg.rx_filter != rx_filter && cfg.rx_filter != rx_filter2 &&
				       cfg.rx_filter != HWTSTAMP_FILTER_ALL)) {
		DEBUG("tx_type   %d not %d", cfg.tx_type, tx_type);
		DEBUG("rx_filter %d not %d or %d", cfg.rx_filter, rx_filter, rx_filter2);
		ERR("The current filter does not match the required");
		return -1;
	}

	return 0;
}

static short sk_events = POLLPRI;
static short sk_revents = POLLPRI;

int sk_receive(int fd, void *buf, int buflen, struct address *addr, struct hw_timestamp *hwts,
	       int flags, int sk_tx_timeout)
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
	if (cnt < 0 && errno != EAGAIN && errno != EINTR) {
		ERR("recvmsg%sfailed: %m", flags == MSG_ERRQUEUE ? " tx timestamp " : " ");
		return cnt;
	}
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		level = cm->cmsg_level;
		type = cm->cmsg_type;
		if (SOL_SOCKET == level && SO_TIMESTAMPING == type) {
			if (cm->cmsg_len < sizeof(*ts) * 3) {
				printf("warning: short SO_TIMESTAMPING message\n");
				return -EMSGSIZE;
			}
			ts = (struct timespec *)CMSG_DATA(cm);
		}
		if (SOL_SOCKET == level && SO_TIMESTAMPNS == type) {
			if (cm->cmsg_len < sizeof(*sw)) {
				printf("warning: short SO_TIMESTAMPNS message\n");
				return -EMSGSIZE;
			}
			sw = (struct timespec *)CMSG_DATA(cm);
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

int raw_send(int fd, enum transport_event event, void *buf, int len, struct hw_timestamp *hwts)
{
	/*struct raw *raw = container_of(t, struct raw, t);*/
	ssize_t cnt;
	unsigned char pkt[1600]; //, *ptr = buf;
	/*struct eth_hdr *hdr;*/
	/*struct tagged_frame_header *tag_hdr;*/
	/*int fd = -1;*/

	/*switch (event) {*/
	/*case TRANS_GENERAL:*/
	/*fd = fda->fd[FD_GENERAL];*/
	/*break;*/
	/*case TRANS_EVENT:*/
	/*case TRANS_ONESTEP:*/
	/*case TRANS_P2P1STEP:*/
	/*case TRANS_DEFER_EVENT:*/
	/*fd = fda->fd[FD_EVENT];*/
	/*break;*/
	/*}*/

	/*if (!addr)*/
	/*addr = peer ? &raw->p2p_addr : &raw->ptp_addr;*/

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
	return event == TRANS_EVENT ?
		       sk_receive(fd, pkt, len, NULL, hwts, MSG_ERRQUEUE, DEFAULT_TX_TIMEOUT) :
		       cnt;
}

int sk_timestamping_destroy(int fd, const char *device, int tstype)
{
	if (tstype == TS_SOFTWARE)
		return 0;
	return hwts_init(fd, device, 0, 0, HWTSTAMP_CLOCK_TYPE_NONE, HWTSTAMP_TX_OFF, 0,
			 HWTSTAMP_DELAY_MECHANISM_OFF, 0);
}

int sk_timestamping_init(int fd, const char *device, int clk_type, enum timestamp_type type,
			 enum transport_type transport, int vclock, int domain,
			 enum delay_mechanism dm, int header_offset)
{
	int err, filter1, filter2 = 0, flags, tx_type = HWTSTAMP_TX_ON;
	struct so_timestamping timestamping;
	enum hwtstamp_delay_mechanism hw_dm;

	switch (type) {
	case TS_SOFTWARE:
		flags = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
			SOF_TIMESTAMPING_SOFTWARE;
		break;
	case TS_HARDWARE:
	case TS_ONESTEP:
	case TS_P2P1STEP:
		flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;
		break;
	case TS_LEGACY_HW:
		flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
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

	if (dm == DM_E2E)
		hw_dm = HWTSTAMP_DELAY_MECHANISM_E2E;
	else if (dm == DM_P2P)
		hw_dm = HWTSTAMP_DELAY_MECHANISM_P2P;
	else
		hw_dm = HWTSTAMP_DELAY_MECHANISM_OFF;

	if (type != TS_SOFTWARE) {
		err = hwts_init(fd, device, filter1, filter2, clk_type, tx_type, domain, hw_dm,
				header_offset);
		if (err && !(type == TS_SOFTWARE && errno == ENOTSUP))
			return err;
	}

	if (vclock >= 0)
		flags |= SOF_TIMESTAMPING_BIND_PHC;

	timestamping.flags = flags;
	timestamping.bind_phc = vclock;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &timestamping, sizeof(timestamping)) < 0) {
		ERR("ioctl SO_TIMESTAMPING failed: %m");
		return -1;
	}

	flags = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE, &flags, sizeof(flags)) < 0) {
		WARN("%s: SO_SELECT_ERR_QUEUE: %m", device);
		sk_events = 0;
		sk_revents = POLLERR;
	}

	/* Enable the sk_check_fupsync option, perhaps. */
	/* if (sk_general_init(fd)) { */
	/* return -1; */
	/* } */

	return 0;
}

static int sk_interface_index(int fd, const char *name)
{
	struct ifreq ifreq;
	int err;

	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, name, sizeof(ifreq.ifr_name) - 1);
	err = ioctl(fd, SIOCGIFINDEX, &ifreq);
	if (err < 0) {
		ERR_NO("ioctl SIOCGIFINDEX failed: %m");
		return err;
	}
	return ifreq.ifr_ifindex;
}

/*
 * tcpdump -d \
 * '   (ether[12:2] == 0x8100 and ether[12 + 4 :2] == 0x88F7 and ether[14+4 :1] & 0x8 == 0x8) '\
 * 'or (ether[12:2] == 0x88F7 and                                ether[14   :1] & 0x8 == 0x8) '
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2    jf 7
 * (002) ldh      [16]
 * (003) jeq      #0x88f7          jt 4    jf 12
 * (004) ldb      [18]
 * (005) and      #0x8
 * (006) jeq      #0x8             jt 11   jf 12
 * (007) jeq      #0x88f7          jt 8    jf 12
 * (008) ldb      [14]
 * (009) and      #0x8
 * (010) jeq      #0x8             jt 11   jf 12
 * (011) ret      #262144
 * (012) ret      #0
*/
static struct sock_filter raw_filter_vlan_norm_general[] = {
	{ 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 5, 0x00008100 }, { 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 8, 0x000088f7 }, { 0x30, 0, 0, 0x00000012 }, { 0x54, 0, 0, 0x00000008 },
	{ 0x15, 4, 5, 0x00000008 }, { 0x15, 0, 4, 0x000088f7 }, { 0x30, 0, 0, 0x0000000e },
	{ 0x54, 0, 0, 0x00000008 }, { 0x15, 0, 1, 0x00000008 }, { 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

/*
 * tcpdump -d \
 *  '   (ether[12:2] == 0x8100 and ether[12 + 4 :2] == 0x88F7 and ether[14+4 :1] & 0x8 != 0x8) '\
 *  'or (ether[12:2] == 0x88F7 and                                ether[14   :1] & 0x8 != 0x8) '
 *
 * (000) ldh      [12]
 * (001) jeq      #0x8100          jt 2    jf 7
 * (002) ldh      [16]
 * (003) jeq      #0x88f7          jt 4    jf 12
 * (004) ldb      [18]
 * (005) and      #0x8
 * (006) jeq      #0x8             jt 12   jf 11
 * (007) jeq      #0x88f7          jt 8    jf 12
 * (008) ldb      [14]
 * (009) and      #0x8
 * (010) jeq      #0x8             jt 12   jf 11
 * (011) ret      #262144
 * (012) ret      #0
 */
static struct sock_filter raw_filter_vlan_norm_event[] = {
	{ 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 5, 0x00008100 }, { 0x28, 0, 0, 0x00000010 },
	{ 0x15, 0, 8, 0x000088f7 }, { 0x30, 0, 0, 0x00000012 }, { 0x54, 0, 0, 0x00000008 },
	{ 0x15, 5, 4, 0x00000008 }, { 0x15, 0, 4, 0x000088f7 }, { 0x30, 0, 0, 0x0000000e },
	{ 0x54, 0, 0, 0x00000008 }, { 0x15, 1, 0, 0x00000008 }, { 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

static int raw_configure(int fd, int event, int index, unsigned char *addr1, unsigned char *addr2,
			 int enable)
{
	int err1, err2, option;
	struct packet_mreq mreq;
	struct sock_fprog prg;

	if (event) {
		prg.len = ARRAY_SIZE(raw_filter_vlan_norm_event);
		prg.filter = raw_filter_vlan_norm_event;
	} else {
		prg.len = ARRAY_SIZE(raw_filter_vlan_norm_general);
		prg.filter = raw_filter_vlan_norm_general;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prg, sizeof(prg))) {
		ERR_NO("setsockopt SO_ATTACH_FILTER failed: %m");
		return -1;
	}

	option = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(mreq.mr_address, addr1, ETH_ALEN);

	err1 = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (err1)
		printf("warning: setsockopt PACKET_MR_MULTICAST failed: %m\n");

	memcpy(mreq.mr_address, addr2, ETH_ALEN);

	err2 = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (err2)
		printf("warning: setsockopt PACKET_MR_MULTICAST failed: %m\n");

	if (!err1 && !err2)
		return 0;

	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_ALLMULTI;
	mreq.mr_alen = 0;
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	printf("warning: setsockopt PACKET_MR_ALLMULTI failed: %m\n");

	mreq.mr_ifindex = index;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;
	if (!setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq))) {
		return 0;
	}
	printf("warning: setsockopt PACKET_MR_PROMISC failed: %m\n");

	ERR("all socket options failed");
	return -1;
}

int open_socket(const char *name, int event, unsigned char *ptp_dst_mac, unsigned char *p2p_dst_mac,
		int socket_priority, int ena_filters)
{
	struct sockaddr_ll addr;
	int fd, index;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		ERR_NO("socket failed: %m");
		goto no_socket;
	}
	index = sk_interface_index(fd, name);
	if (index < 0)
		goto no_option;

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		ERR_NO("bind failed: %m");
		goto no_option;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name))) {
		ERR_NO("setsockopt SO_BINDTODEVICE failed: %m");
		goto no_option;
	}

	if (socket_priority > 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &socket_priority, sizeof(socket_priority))) {
		ERR_NO("setsockopt SO_PRIORITY failed: %m");
		goto no_option;
	}
	if (ena_filters && raw_configure(fd, event, index, ptp_dst_mac, p2p_dst_mac, 1))
		goto no_option;

	return fd;
no_option:
	close(fd);
no_socket:
	return -1;
}

void print_ts(char *text, int64_t ns)
{
	printf("%s%" PRId64 ".%09" PRId64 "\n", text, ns / NS_PER_SEC, ns % NS_PER_SEC);
}

void DBG_print_ts(char *text, int64_t ns)
{
	DEBUG("%s: %" PRId64 ".%09" PRId64 "\n", text, ns / NS_PER_SEC, ns % NS_PER_SEC);
}
