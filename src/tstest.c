// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
/*
 * Copyright 2019 NXP
 */

#include <stdio.h>
#include <stdlib.h>
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

#include "tstest.h"

#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING         37
# define SCM_TIMESTAMPING        SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
# define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
# define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
# define SIOCSHWTSTAMP 0x89b0
#endif

static int txcount = 0;
static int txcount_flag = 0;
static int nonstop_flag = 0;
/*static int fully_send = 0;*/
static int rx_only = 0;
static int tx_only = 0;
static int debugen = 0;
/*static int delay_us = 0;*/
/*static int send_now = 0;*/
#ifndef CLOCK_TAI
#define CLOCK_TAI                       11
#endif

#ifndef SCM_TXTIME
#define SO_TXTIME               61
#define SCM_TXTIME              SO_TXTIME
#endif
#define _DEBUG(file, fmt, ...) do { \
	if (debugen) { \
		fprintf(file, " " fmt, \
		##__VA_ARGS__); \
	} else { \
		; \
	} \
} while (0)

#define DEBUG(...) _DEBUG(stderr, __VA_ARGS__)

static void bail(const char *error)
{
	printf("%s: %s\n", error, strerror(errno));
	exit(1);
}

void help()
{
	printf("send one ARP package \n \
			-i <interface> \n \
			-r RECEIVE MODE \n \
			-l <length> \n \
			-m <source macaddr> \n \
			-c <frame counts> \n \
			-p <priority> \n \
			-b <debug enable> \n \
			-d <delay us> \n \
			-h help \
			\n");
}
/*static unsigned char sync_packet[] = {*/
	/*0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, [> dmac <]*/
	/*0x11, 0x00, 0x80, 0x00, 0x00, 0x00,*/
	/*0x08, 0x00,		[> eth header <]*/
	/*0x45, 0x00,			[> hardware type <]*/
	/*0x08, 0x00,		[> IP type <]*/
	/*0x06, 0x04,			[> hw len, protocol len <]*/
	/*0x00, 0x01,			[> request type: 1: ARP, 2: ARP REPLY <]*/
	/*0x00, 0x00, 0xff, 0x00, 0x00, 0x00,		[> source mac <]*/
	/*0x09, 0x09, 0x09, 0x09,*/
	/*0x00, 0x00,	0x00, 0x00,	0x00, 0x00,*/
	/*0x0a, 0x0a, 0x0a, 0x0a,*/
	/*0x00, 0x80,*/
	/*0x00, 0xb0,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,	[> correctionField <]*/
	/*0x00, 0x00, 0x00, 0x00,	[> reserved <]*/
	/*0x00, 0x04, 0x9f, 0xff,*/
	/*0xfe, 0x03, 0xd9, 0xe0,*/
	/*0x00, 0x01,		[> sourcePortIdentity <]*/
	/*0x00, 0x1d,		[> sequenceId <]*/
	/*0x00,			[> controlField <]*/
	/*0x00,			[> logMessageInterval <]*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00,		[> originTimestamp <]*/
	/*0x00, 0x00, 0x00, 0x00,*/
	/*0x00, 0x00		[> originTimestamp <]*/
/*};*/

//static unsigned char sync_packet[] = {
//	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dmac
//	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, // smac
//	0x88, 0xf7, // PTPv2 ethertype
//	0x00, // majorSdoId, messageType (0x0=Sync)
//	0x02, // minorVersionPtp, versionPTP
//	0x00, 0x2c, // messageLength
//	0xff, // domainNumber (use domain number 0xff for this)
//	0x00, // majorSdoId
//	0x02, 0x00, // flags
//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // correctionField
//	0x00, 0x00, 0x00, 0x00, // messageTypeSpecific
//	0xbb, 0xbb, 0xbb, 0xff, 0xfe, 0xbb, 0xbb, 0xbb, // clockIdentity
//	0x00, 0x01, // sourcePort
//	0x00, 0x00, // sequenceId
//	0x00, // controlField
//	0x00, // logMessagePeriod
//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // originTimestamp (seconds)
//	0x00, 0x00, 0x00, 0x00, // originTimestamp (nanoseconds)
//};


int ptp_type;
union Message message;


#define MAC_LEN  6
int str2mac(const char *s, unsigned char mac[MAC_LEN])
{
	unsigned char buf[MAC_LEN];
	int c;
	c = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
	if (c != MAC_LEN) {
		return -1;
	}
	memcpy(mac, buf, MAC_LEN);
	return 0;
}

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

static void sendpacket(int sock, unsigned char *mac)
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

	if (debugen)
		gettimeofday(&now, 0);

	DEBUG("%ld.%06ld: received %s data, %d bytes from %s, %zu bytes control messages\n",
	       (long)now.tv_sec, (long)now.tv_usec,
	       (recvmsg_flags & MSG_ERRQUEUE) ? "error" : "regular",
	       res,
	       inet_ntoa(from_addr->sin_addr),
	       msg->msg_controllen);
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

void *rcv_pkt(void *data)
{
	int res;
	fd_set readfs, errorfs;
	int sock;

	sock = *(int *)data;

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

	return 0;
}

static void setsockopt_txtime(int fd)
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


int main(int argc, char **argv)
{
	int so_timestamping_flags = 0;
	char *interface = NULL;
	int sock;
	struct ifreq device;
	struct ifreq hwtstamp;
	struct hwtstamp_config hwconfig, hwconfig_requested;
	struct sockaddr_ll addr;
	int val;
	Octet mac[MAC_LEN]; // = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	socklen_t len;
	unsigned int length = 0;
	int c;
	int count = 1;
	int prio = 0;
	int seq = 0;
	int one_step = 0;
	/*int ptp_type = 0;*/
	int tstamp_all = 0;
	pthread_t receive_pkt;
	struct ptp_header hdr;

	str2mac("ff:ff:ff:ff:ff:ff", mac);

	while ((c = getopt (argc, argv, "trapdhoi:m:c:s:T:")) != -1) {
		switch (c)
		{
			case 'T':
				/*ptp_type = strtoul(optarg, NULL, 0);*/
				ptp_type = str2ptp_type(optarg);
				if (ptp_type < 0) {
					printf("Invalid ptp type\n");
					return -1;
				}
				break;
			case 'a':
				tstamp_all = 1;
				break;
			case 'o':
				one_step = 1;
				break;
			case 's':
				seq = strtoul(optarg, NULL, 0);
				break;
			case 't':
				tx_only = 1;
				break;
			case 'i':
				interface = optarg;
				break;
			/*case 'f':*/
				/*fully_send = 1;*/
				/*break;*/
			case 'r':
				rx_only = 1;
				break;
			/*case 'l':*/
				/*length = strtoul(optarg, NULL, 0);*/
				/*break;*/
			case 'm':
				if (str2mac(optarg, mac))
					printf("error mac input\n");
				break;
			case 'c':
				count = strtoul(optarg, NULL, 0);
				break;
			case 'p':
				prio = strtoul(optarg, NULL, 0);
				break;
			case 'd':
				debugen = 1;
				break;
			/*case 'd':*/
				/*delay_us = strtoul(optarg, NULL, 0);*/
				/*break;*/
			/*case 'n':*/
				/*send_now = 1;*/
				/*break;*/
			case 'h':
				help();
				return -1;
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else
					fprintf (stderr,
						"Unknown option character `\\x%x'.\n",
						optopt);
				return 1;
			default:
				help();
				return -1;
		}
	}

	hdr = ptp_header_template();
	ptp_set_type(&hdr, ptp_type);
	ptp_set_seqId(&hdr, seq);
	ptp_set_dmac(&hdr, mac);

	message = ptp_msg_create_type(hdr, ptp_type);

	if (!interface) {
		fprintf(stderr, "Error: missing input interface\n");
		exit(EINVAL);
	}

	if (tx_only && rx_only) {
		printf("Cannot combine -t and -r\n");
		exit(EINVAL);
	}


	so_timestamping_flags |= (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_OPT_TSONLY);
	so_timestamping_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
	so_timestamping_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		bail("socket");

	memset(&device, 0, sizeof(device));
	strncpy(device.ifr_name, interface, sizeof(device.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &device) < 0)
		bail("getting interface index");

	/* Set the SIOCSHWTSTAMP ioctl */
	memset(&hwtstamp, 0, sizeof(hwtstamp));
	strncpy(hwtstamp.ifr_name, interface, sizeof(hwtstamp.ifr_name));
	hwtstamp.ifr_data = (void *)&hwconfig;
	memset(&hwconfig, 0, sizeof(hwconfig));

	if (so_timestamping_flags & SOF_TIMESTAMPING_TX_HARDWARE) {
		if (one_step)
			hwconfig.tx_type = HWTSTAMP_TX_ONESTEP_SYNC;
		else
			hwconfig.tx_type = HWTSTAMP_TX_ON;
	} else {
		hwconfig.tx_type = HWTSTAMP_TX_OFF;
	}

	if (tstamp_all) {
		hwconfig.rx_filter =
			(so_timestamping_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
			HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;
	} else {
		hwconfig.rx_filter =
			(so_timestamping_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
			HWTSTAMP_FILTER_PTP_V2_SYNC : HWTSTAMP_FILTER_NONE;
	}
	if (tx_only)
		hwconfig.rx_filter = 0;

	hwconfig_requested = hwconfig;
	if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp) < 0) {
		if ((errno == EINVAL || errno == ENOTSUP) &&
		    hwconfig_requested.tx_type == HWTSTAMP_TX_OFF &&
		    hwconfig_requested.rx_filter == HWTSTAMP_FILTER_NONE)
			printf("SIOCSHWTSTAMP: disabling hardware time stamping not possible\n");
		else
			printf("SIOCSHWTSTAMP: operation not supported!\n");
	}
	printf("SIOCSHWTSTAMP: tx_type %d requested, got %d; rx_filter %d requested, got %d\n",
	       hwconfig_requested.tx_type, hwconfig.tx_type,
	       hwconfig_requested.rx_filter, hwconfig.rx_filter);

	/* bind to PTP port */
	addr.sll_ifindex = device.ifr_ifindex;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock,
		 (struct sockaddr *)&addr,
		 sizeof(struct sockaddr_ll)) < 0)
		bail("bind");
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)))
		bail("setsockopt SO_BINDTODEVICE");
	if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(int)))
		bail("setsockopt SO_PRIORITY");

	if (so_timestamping_flags &&
		setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING,
			   &so_timestamping_flags,
			   sizeof(so_timestamping_flags)) < 0)
		printf("setsockopt SO_TIMESTAMPING not supported\n");

	/* verify socket options */
	len = sizeof(val);

	if (getsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &val, &len) < 0) {
		printf("%s: %s\n", "getsockopt SO_TIMESTAMPING",
			strerror(errno));
	} else {
		printf("SO_TIMESTAMPING %d\n", val);
		if (val != so_timestamping_flags)
			printf("   not the expected value %d\n",
			       so_timestamping_flags);
	}

	setsockopt_txtime(sock);

	printf("\n");
	txcount = count;
	if (!count)
		nonstop_flag = 1;

	if (rx_only) {
		while(1)
			rcv_pkt(&sock);
	}

	/*if (fully_send)*/
		/*pthread_create(&receive_pkt, NULL, rcv_pkt, &sock);*/

	while (count || nonstop_flag) {
		/* write one packet */
		sendpacket(sock, mac);
		if (!nonstop_flag)
			count--;
		/*if (!fully_send) {*/
		txcount_flag = 0;
		if (!one_step)
			rcv_pkt(&sock);
		/*}*/
	}

	/*if (fully_send) {*/
		/*pthread_join(receive_pkt, NULL);*/
		/*pthread_cancel(receive_pkt);*/
	/*}*/

	return 0;
}
