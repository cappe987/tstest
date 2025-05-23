// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "liblink.h"
/* Get the index of the interface to send on */
int get_iface_index(int sockfd, char iface[IFNAMSIZ])
{
	struct ifreq buffer = { 0 };

	memset(&buffer, 0, sizeof(struct ifreq));
	/*#pragma GCC diagnostic ignored "-Wstringop-truncation"*/
	strncpy(buffer.ifr_name, iface, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFINDEX, &buffer) < 0) {
		ERR("No such device: %s", iface);
		return -1;
	}

	return buffer.ifr_ifindex;
}

int get_smac(int sockfd, char ifname[IFNAMSIZ], unsigned char smac[6])
{
	struct ifreq buffer = { 0 };
	memcpy(buffer.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFHWADDR, &buffer) < 0) {
		printf("smac %2X\n", buffer.ifr_hwaddr.sa_data[0]);
		perror("Error");
		ERR("Unable to find source MAC");
		return -ENOENT;
	}
	memcpy(smac, (buffer.ifr_hwaddr.sa_data), ETH_ALEN);
	return 0;
}

int get_iface_mac(char ifname[IFNAMSIZ], unsigned char mac_address[ETH_ALEN])
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) { /* handle error*/
	};

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */
	}

	struct ifreq *it = ifc.ifc_req;
	const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (!(ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		} else { /* handle error */
		}
	}

	if (success)
		memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	close(sock);
	return 0;
}

void set_dmac(unsigned char *frame, unsigned char mac[ETH_ALEN])
{
	for (int i = 0; i < ETH_ALEN; i++)
		frame[i] = mac[i];
}

void set_smac(unsigned char *frame, unsigned char mac[ETH_ALEN])
{
	for (int i = 0; i < ETH_ALEN; i++)
		frame[6 + i] = mac[i];
}

int str2mac(const char *s, unsigned char mac[ETH_ALEN])
{
	unsigned char buf[ETH_ALEN];
	int c;
	c = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &buf[0], &buf[1], &buf[2], &buf[3], &buf[4],
		   &buf[5]);
	if (c != ETH_ALEN) {
		return -1;
	}
	memcpy(mac, buf, ETH_ALEN);
	return 0;
}
