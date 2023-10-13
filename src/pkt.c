// SPDX-License-Identifier: GPL-2.0-only
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

#include "tstest.h"
#include "liblink.h"
#include "timestamping.h"

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
#define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
#define SIOCSHWTSTAMP 0x89b0
#endif

extern int txcount;
extern int txcount_flag;
extern int nonstop_flag;
extern int rx_only;
extern int tx_only;
extern int debugen;
extern int ptp_type;
extern union Message message;

static void bail(const char *error)
{
	printf("%s: %s\n", error, strerror(errno));
	exit(1);
}

void pkt_help()
{
	fprintf(stderr, "\n--- TSTest Packets ---\n\n");
	fprintf(stderr, "Transmits and receives PTP packets and outputs the timestamps.\n\n\
Usage:\n\
        tstest pkt [options]\n\n\
Options:\n\
        -i <interface> \n\
        -T <PTP type> \n\
        -t TX only mode \n\
        -r RX only mode \n\
        -a Timestamp all packets \n\
        -o Use one-step timestamping \n\
        -s <sequence id> \n\
        -m <destination MAC> \n\
        -c <frame counts> \n\
        -p <priority> \n\
        -d Enable debug output\n\
        -h help\n\
        \n");
}

int send_auto_fup(int sock, int ptp_type, int seq, char *mac, int transportSpecific, int version, int domain)
{
	struct ptp_header hdr;
	union Message msg;
	int err;

	if (ptp_type == SYNC)
		ptp_type = FOLLOW_UP;
	else if (ptp_type == PDELAY_RESP)
		ptp_type = PDELAY_RESP_FUP;
	else
		return -EINVAL;

	hdr = ptp_header_template();
	ptp_set_type(&hdr, ptp_type);
	ptp_set_seqId(&hdr, seq);
	ptp_set_dmac(&hdr, mac);
	ptp_set_transport_specific(&hdr, transportSpecific);
	ptp_set_version(&hdr, version);
	ptp_set_domain(&hdr, domain);
	ptp_set_flags(&hdr, 0);

	msg = ptp_msg_create_type(hdr, ptp_type);
	return raw_send(sock, TRANS_GENERAL, &msg, ptp_msg_get_size(ptp_type), NULL);
}

int run_pkt_mode(int argc, char **argv)
{
	int so_timestamping_flags = 0;
	char *interface = NULL;
	int sock;
	struct ifreq device;
	struct ifreq hwtstamp;
	struct hwtstamp_config hwconfig, hwconfig_requested;
	struct sockaddr_ll addr;
	int val;
	Octet mac[ETH_ALEN]; // = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	socklen_t len;
	unsigned int length = 0;
	int c;
	int count = 1;
	int prio = 0;
	int seq = 0;
	int domain = 0;
	int version = 2 | (1 << 4);
	int one_step = 0;
	int twoStepFlag = 1;
	int twoStepFlag_set = 0;
	int one_step_listen = 0;
	int transportSpecific = 0;
	int auto_fup = 0;
	/*int ptp_type = 0;*/
	int tstamp_all = 0;
	pthread_t receive_pkt;
	int tstype = TS_HARDWARE;
	struct ptp_header hdr;
	int err;

	struct option long_options[] = { { "help", no_argument, NULL, 'h' },
					 { "transportSpecific", required_argument, NULL, 1 },
					 { "twoStepFlag", required_argument, NULL, 2 },
					 { NULL, 0, NULL, 0 } };

	if (argc == 1) {
		pkt_help();
		return EINVAL;
	}

	str2mac("ff:ff:ff:ff:ff:ff", mac);

	while ((c = getopt_long(argc, argv, "StrapdfD:hoOi:m:c:s:T:v:", long_options, NULL)) != -1) {
		switch (c) {
		case 1:
			transportSpecific = strtoul(optarg, NULL, 0);
			break;
		case 2:
			twoStepFlag = strtoul(optarg, NULL, 0);
			twoStepFlag_set = 1;
			break;
		case 'T':
			ptp_type = str2ptp_type(optarg);
			if (ptp_type < 0) {
				printf("Invalid ptp type\n");
				return -1;
			}
			break;
		case 'S':
			tstype = TS_SOFTWARE;
			break;
		case 'a':
			tstamp_all = 1;
			break;
		case 'o':
			one_step = 1;
			tstype = TS_ONESTEP;
			break;
		case 'O':
			tstype = TS_ONESTEP;
			one_step_listen = 1;
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
		case 'f':
			auto_fup = 1;
			break;
		case 'D':
			domain = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			if (optarg == NULL)
				printf("bad version input\n");
			else if (strncmp(optarg, "2.1", 3) == 0)
				version = 2 | (1 << 4);
			else if (strncmp(optarg, "2", 1) == 0)
				version = 2;
			else
				printf("bad version input\n");
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
			pkt_help();
			return -1;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			pkt_help();
			return -1;
		}
	}

	hdr = ptp_header_template();
	ptp_set_type(&hdr, ptp_type);
	ptp_set_seqId(&hdr, seq);
	ptp_set_dmac(&hdr, mac);
	ptp_set_transport_specific(&hdr, transportSpecific);
	ptp_set_version(&hdr, version);
	ptp_set_domain(&hdr, domain);

	if (!interface) {
		fprintf(stderr, "Error: missing input interface\n");
		return EINVAL;
	}

	if (tx_only && rx_only) {
		fprintf(stderr, "Error: cannot combine -t and -r\n");
		return EINVAL;
	}

	if (auto_fup && (ptp_type != SYNC && ptp_type != PDELAY_RESP)) {
		fprintf(stderr, "Error: auto-follow-up can only be used with sync and pdelay_resp\n");
		return EINVAL;
	}

	if (one_step_listen)
		one_step = 1;

	if (twoStepFlag_set) {
		if (twoStepFlag)
			ptp_set_flags(&hdr, 0x02);
		else
			ptp_set_flags(&hdr, 0x00);
	} else {
		/* Auto-clear twoStepFlag when one-step sync is set.
		 * Later this also needs to handle p2p1step.
		 */
		if (one_step && ptp_type == SYNC)
			ptp_set_flags(&hdr, 0);
	}

	message = ptp_msg_create_type(hdr, ptp_type);

	//so_timestamping_flags |= (SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_OPT_TSONLY);
	//so_timestamping_flags |= (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_OPT_CMSG);
	//so_timestamping_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;

	//sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	//if (sock < 0)
	//	bail("socket");

	//memset(&device, 0, sizeof(device));
	//strncpy(device.ifr_name, interface, sizeof(device.ifr_name));
	//if (ioctl(sock, SIOCGIFINDEX, &device) < 0)
	//	bail("getting interface index");

	///* Set the SIOCSHWTSTAMP ioctl */
	//memset(&hwtstamp, 0, sizeof(hwtstamp));
	//strncpy(hwtstamp.ifr_name, interface, sizeof(hwtstamp.ifr_name));
	//hwtstamp.ifr_data = (void *)&hwconfig;
	//memset(&hwconfig, 0, sizeof(hwconfig));

	//if (so_timestamping_flags & SOF_TIMESTAMPING_TX_HARDWARE) {
	//	if (one_step)
	//		hwconfig.tx_type = HWTSTAMP_TX_ONESTEP_SYNC;
	//	else
	//		hwconfig.tx_type = HWTSTAMP_TX_ON;
	//} else {
	//	hwconfig.tx_type = HWTSTAMP_TX_OFF;
	//}

	//if (tstamp_all) {
	//	hwconfig.rx_filter = (so_timestamping_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
	//				     HWTSTAMP_FILTER_ALL :
	//				     HWTSTAMP_FILTER_NONE;
	//} else {
	//	hwconfig.rx_filter = (so_timestamping_flags & SOF_TIMESTAMPING_RX_HARDWARE) ?
	//				     HWTSTAMP_FILTER_PTP_V2_SYNC :
	//				     HWTSTAMP_FILTER_NONE;
	//}
	//if (tx_only)
	//	hwconfig.rx_filter = 0;

	//hwconfig_requested = hwconfig;
	//if (ioctl(sock, SIOCSHWTSTAMP, &hwtstamp) < 0) {
	//	if ((errno == EINVAL || errno == ENOTSUP) &&
	//	    hwconfig_requested.tx_type == HWTSTAMP_TX_OFF &&
	//	    hwconfig_requested.rx_filter == HWTSTAMP_FILTER_NONE) {
	//		fprintf(stderr,
	//			"SIOCSHWTSTAMP: disabling hardware time stamping not possible\n");
	//		return EINVAL;
	//	} else {
	//		fprintf(stderr, "SIOCSHWTSTAMP: operation not supported!\n");
	//		return EINVAL;
	//	}
	//}
	//printf("SIOCSHWTSTAMP: tx_type %d requested, got %d; rx_filter %d requested, got %d\n",
	//       hwconfig_requested.tx_type, hwconfig.tx_type, hwconfig_requested.rx_filter,
	//       hwconfig.rx_filter);

	///* bind to PTP port */
	//addr.sll_ifindex = device.ifr_ifindex;
	//addr.sll_family = AF_PACKET;
	//addr.sll_protocol = htons(ETH_P_ALL);
	//if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0)
	//	bail("bind");
	//if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)))
	//	bail("setsockopt SO_BINDTODEVICE");
	//if (setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(int)))
	//	bail("setsockopt SO_PRIORITY");

	//if (so_timestamping_flags &&
	//    setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags,
	//	       sizeof(so_timestamping_flags)) < 0)
	//	printf("setsockopt SO_TIMESTAMPING not supported\n");

	///* verify socket options */
	//len = sizeof(val);

	//if (getsockopt(sock, SOL_SOCKET, SO_TIMESTAMPING, &val, &len) < 0) {
	//	printf("%s: %s\n", "getsockopt SO_TIMESTAMPING", strerror(errno));
	//} else {
	//	printf("SO_TIMESTAMPING %d\n", val);
	//	if (val != so_timestamping_flags)
	//		printf("   not the expected value %d\n", so_timestamping_flags);
	//}

	//setsockopt_txtime(sock);

	/*printf("\n");*/
	txcount = count;
	if (!count)
		nonstop_flag = 1;


	/* Using this new method the tstamp_all will not work. Will
	 * pdelay_req/resp work correctly with one-step/p2p1step?
	 */
	unsigned char buf[1600];
	struct hw_timestamp hwts;
	union Message *msg;

	msg = (union Message*) buf;

	hwts.type = tstype;
	sock = open_socket(interface, 1, NULL, NULL, 0, 0);
	if (sock < 0) {
		ERR_NO("failed to open socket");
		return sock;
	}

	err = sk_timestamping_init(sock, interface, tstype, TRANS_IEEE_802_3, -1);
	if (err < 0) {
		ERR_NO("failed to enable timestamping");
		return err;
	}

	if (rx_only) {
		while (1) {
			sk_receive(sock, msg, 1600, NULL, &hwts, 0);
			printf("%ld.%ld. Type %s\n",
				hwts.ts.ns / NS_PER_SEC, hwts.ts.ns % NS_PER_SEC,
				ptp_type2str(msg->hdr.tsmt & 0xF));
		}
	}

	/*if (fully_send)*/
	/*pthread_create(&receive_pkt, NULL, rcv_pkt, &sock);*/

	enum transport_event event_type = ptp_type & 0x8 ? TRANS_GENERAL : TRANS_EVENT;

	while (count || nonstop_flag) {
		/* write one packet */
		/*sendpacket(sock, mac);*/
		raw_send(sock, event_type, &message, ptp_msg_get_size(ptp_type), &hwts);
		printf("%ld.%ld\n",
			hwts.ts.ns / NS_PER_SEC, hwts.ts.ns % NS_PER_SEC);
		if (!nonstop_flag)
			count--;
		/*if (!fully_send) {*/
		if (auto_fup) {
			send_auto_fup(sock, ptp_type, seq, mac, transportSpecific, version, domain);
		}
		/*else {*/
			/*txcount_flag = 0;*/
			/*if (!one_step || one_step_listen)*/
				/*rcv_pkt(sock);*/
		/*}*/
		/*}*/
	}

	/*if (fully_send) {*/
	/*pthread_join(receive_pkt, NULL);*/
	/*pthread_cancel(receive_pkt);*/
	/*}*/

	return 0;
}
