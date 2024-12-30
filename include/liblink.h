// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#ifndef __LIBLINK_H__
#define __LIBLINK_H__

#include <net/if.h>

#define ERR(str, ...) fprintf(stderr, "Error: " str "\n", ##__VA_ARGS__)
#define ERR_NO(str, ...) fprintf(stderr, "Error: " str ": %s\n", ##__VA_ARGS__, strerror(errno))
#define WARN(str, ...) fprintf(stderr, "Warn: " str "\n", ##__VA_ARGS__)

#define _DEBUG(file, fmt, ...)                                                                     \
	do {                                                                                       \
		if (debugen) {                                                                     \
			fprintf(file, "debug: " fmt, ##__VA_ARGS__);                               \
		}                                                                                  \
	} while (0)

#define DEBUG(...) _DEBUG(stderr, __VA_ARGS__)

int get_iface_index(int sockfd, char iface[IFNAMSIZ]);
int get_smac(int sockfd, char ifname[IFNAMSIZ], unsigned char smac[6]);
int get_iface_mac(char ifname[IFNAMSIZ], unsigned char mac_address[ETH_ALEN]);
void set_dmac(unsigned char *frame, unsigned char mac[ETH_ALEN]);
void set_smac(unsigned char *frame, unsigned char mac[ETH_ALEN]);
int str2mac(const char *s, unsigned char mac[ETH_ALEN]);

#endif /* __LIBLINK_H__ */
