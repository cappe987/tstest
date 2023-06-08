// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
//

#define _GNU_SOURCE

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
#include <sys/ioctl.h>
#include <linux/ptp_clock.h>
#include <linux/limits.h>
#include <sys/timex.h>
#include <sys/stat.h>
#include <fcntl.h>


#define pr_err(...) fprintf(stderr, __VA_ARGS__)


#define CLOCK_INVALID -1
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))
#define BITS_PER_LONG	(sizeof(long)*8)
#define MAX_PPB_32	32767999	/* 2^31 - 1 / 65.536 */

/*
 * Bits of the ptp_extts_request.flags field:
 */
#define PTP_ENABLE_FEATURE (1<<0)
#define PTP_RISING_EDGE    (1<<1)
#define PTP_FALLING_EDGE   (1<<2)
#define PTP_STRICT_FLAGS   (1<<3)
#define PTP_EXTTS_EDGES    (PTP_RISING_EDGE | PTP_FALLING_EDGE)

#ifdef PTP_PIN_SETFUNC2
#define PTP_PIN_SETFUNC_FAILED "PTP_PIN_SETFUNC2 failed: %m\n"
#else
#define PTP_PIN_SETFUNC_FAILED "PTP_PIN_SETFUNC failed: %m\n"
#define PTP_PIN_SETFUNC2 PTP_PIN_SETFUNC
#endif

#ifdef PTP_EXTTS_REQUEST2
#define PTP_EXTTS_REQUEST_FAILED "PTP_EXTTS_REQUEST2 failed: %m\n"
#else
#define PTP_EXTTS_REQUEST_FAILED "PTP_EXTTS_REQUEST failed: %m\n"
#define PTP_EXTTS_REQUEST2 PTP_EXTTS_REQUEST
#endif


struct ts2phc_clock {
	/*LIST_ENTRY(ts2phc_clock) list;*/
	clockid_t clkid;
	int fd;
	int phc_index;
	/*enum port_state state;*/
	/*enum port_state new_state;*/
	/*struct servo *servo;*/
	/*enum servo_state servo_state;*/
	char *name;
	/*bool no_adj;*/
	/*bool is_target;*/
	/*bool is_ts_available;*/
	/*tmv_t last_ts;*/
};


/**
 * Contains timestamping information returned by the GET_TS_INFO ioctl.
 * @valid:            set to non-zero when the info struct contains valid data.
 * @phc_index:        index of the PHC device.
 * @so_timestamping:  supported time stamping modes.
 * @tx_types:         driver level transmit options for the HWTSTAMP ioctl.
 * @rx_filters:       driver level receive options for the HWTSTAMP ioctl.
 */
struct sk_ts_info {
	int valid;
	int phc_index;
	unsigned int so_timestamping;
	unsigned int tx_types;
	unsigned int rx_filters;
};

/**
 * Values returned by get_ranged_*().
 */
enum parser_result {
	PARSED_OK,
	NOT_PARSED,
	BAD_VALUE,
	MALFORMED,
	OUT_OF_RANGE,
};


clockid_t phc_open(const char *phc)
{
	clockid_t clkid;
	struct timespec ts;
	struct timex tx;
	int fd;

	memset(&tx, 0, sizeof(tx));

	fd = open(phc, O_RDWR);
	if (fd < 0)
		return CLOCK_INVALID;

	clkid = FD_TO_CLOCKID(fd);
	/* check if clkid is valid */
	if (clock_gettime(clkid, &ts)) {
		close(fd);
		return CLOCK_INVALID;
	}
	if (clock_adjtime(clkid, &tx)) {
		close(fd);
		return CLOCK_INVALID;
	}

	return clkid;
}

void phc_close(clockid_t clkid)
{
	if (clkid == CLOCK_INVALID)
		return;

	close(CLOCKID_TO_FD(clkid));
}

static int phc_get_caps(clockid_t clkid, struct ptp_clock_caps *caps)
{
	int fd = CLOCKID_TO_FD(clkid), err;

	err = ioctl(fd, PTP_CLOCK_GETCAPS, caps);
	if (err)
		perror("PTP_CLOCK_GETCAPS");
	return err;
}

int phc_max_adj(clockid_t clkid)
{
	int max;
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps))
		return 0;

	max = caps.max_adj;

	if (BITS_PER_LONG == 32 && max > MAX_PPB_32)
		max = MAX_PPB_32;

	return max;
}

int phc_number_pins(clockid_t clkid)
{
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps)) {
		return 0;
	}
	return caps.n_pins;
}

int phc_pin_setfunc(clockid_t clkid, struct ptp_pin_desc *desc)
{
	int err = ioctl(CLOCKID_TO_FD(clkid), PTP_PIN_SETFUNC2, desc);
	if (err) {
		fprintf(stderr, PTP_PIN_SETFUNC_FAILED "\n");
	}
	return err;
}

int phc_has_pps(clockid_t clkid)
{
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps))
		return 0;
	return caps.pps;
}

int phc_has_writephase(clockid_t clkid)
{
	struct ptp_clock_caps caps;

	if (phc_get_caps(clkid, &caps)) {
		return 0;
	}
	return caps.adjust_phase;
}

enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max)
{
	long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtol(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

int sk_get_ts_info(const char *name, struct sk_ts_info *sk_info)
{
#ifdef ETHTOOL_GET_TS_INFO
	struct ethtool_ts_info info;
	struct ifreq ifr;
	int fd, err;

	memset(&ifr, 0, sizeof(ifr));
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GET_TS_INFO;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	ifr.ifr_data = (char *) &info;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		pr_err("socket failed: %m\n");
		goto failed;
	}

	err = ioctl(fd, SIOCETHTOOL, &ifr);
	if (err < 0) {
		pr_err("ioctl SIOCETHTOOL failed: %m\n");
		close(fd);
		goto failed;
	}

	close(fd);

	/* copy the necessary data to sk_info */
	memset(sk_info, 0, sizeof(struct sk_ts_info));
	sk_info->valid = 1;
	sk_info->phc_index = info.phc_index;
	sk_info->so_timestamping = info.so_timestamping;
	sk_info->tx_types = info.tx_types;
	sk_info->rx_filters = info.rx_filters;

	return 0;
failed:
#endif
	/* clear data and ensure it is not marked valid */
	memset(sk_info, 0, sizeof(struct sk_ts_info));
	return -1;
}

clockid_t posix_clock_open(const char *device, int *phc_index)
{
	char phc_device_path[PATH_MAX];
	struct sk_ts_info ts_info;
	char phc_device[19];
	int clkid;

	/* check if device is CLOCK_REALTIME */
	if (!strcasecmp(device, "CLOCK_REALTIME")) {
		return CLOCK_REALTIME;
	}

	/* if the device name resolves so a plausible filesystem path, we
	 * assume it is the path to a PHC char device, and treat it as such
	 */
	if (realpath(device, phc_device_path)) {
		clkid = phc_open(device);
		if (clkid == CLOCK_INVALID)
			return clkid;

		if (!strncmp(phc_device_path, "/dev/ptp", strlen("/dev/ptp"))) {
			int r = get_ranged_int(phc_device_path + strlen("/dev/ptp"),
					       phc_index, 0, 65535);
			if (r) {
				fprintf(stderr,
					"failed to parse PHC index from %s\n",
					phc_device_path);
				phc_close(clkid);
				return CLOCK_INVALID;
			}
		}
		return clkid;
	}

	/* check if device is a valid ethernet device */
	if (sk_get_ts_info(device, &ts_info) || !ts_info.valid) {
		pr_err("unknown clock %s: %m\n", device);
		return CLOCK_INVALID;
	}
	if (ts_info.phc_index < 0) {
		pr_err("interface %s does not have a PHC\n", device);
		return CLOCK_INVALID;
	}
	snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d\n", ts_info.phc_index);
	clkid = phc_open(phc_device);
	if (clkid == CLOCK_INVALID) {
		pr_err("cannot open %s for %s: %m\n", phc_device, device);
	}
	*phc_index = ts_info.phc_index;
	return clkid;
}

void posix_clock_close(clockid_t clock)
{
	if (clock == CLOCK_REALTIME) {
		return;
	}
	phc_close(clock);
}


struct ts2phc_clock *ts2phc_clock_add(const char *device)
{
	clockid_t clkid = CLOCK_INVALID;
	struct ts2phc_clock *c;
	int phc_index = -1;
	int err;

	clkid = posix_clock_open(device, &phc_index);
	if (clkid == CLOCK_INVALID)
		return NULL;

//	LIST_FOREACH(c, &priv->clocks, list) {
//		if (c->phc_index == phc_index) {
//			/* Already have the clock, don't add it again */
//			posix_clock_close(clkid);
//			return c;
//		}
//	}

	c = calloc(1, sizeof(*c));
	if (!c) {
		pr_err("failed to allocate memory for a clock\n");
		return NULL;
	}
	c->clkid = clkid;
	c->fd = CLOCKID_TO_FD(clkid);
	c->phc_index = phc_index;
	/*c->servo_state = SERVO_UNLOCKED;*/
	/*c->servo = ts2phc_servo_create(priv, c);*/
	/*c->no_adj = config_get_int(priv->cfg, NULL, "free_running");*/
	err = asprintf(&c->name, "/dev/ptp%d", phc_index);
	if (err < 0) {
		free(c);
		posix_clock_close(clkid);
		return NULL;
	}

	/*LIST_INSERT_HEAD(&priv->clocks, c, list);*/
	return c;
}




int run_extts_mode(int argc, char **argv)
{
	struct ptp_extts_request extts;
	struct ts2phc_clock *clock;

	clock = ts2phc_clock_add("eth0");

	if (!clock)
		return -EINVAL;


	/*
	* Disable external time stamping, and then read out any stale
	* time stamps.
	*/
	memset(&extts, 0, sizeof(extts));
	extts.index = 0;
	extts.flags = 0;
	if (ioctl(clock->fd, PTP_EXTTS_REQUEST2, &extts)) {
		pr_err(PTP_EXTTS_REQUEST_FAILED);
	}
	/*if (ts2phc_pps_sink_clear_fifo(sink)) {*/
		/*goto no_ext_ts;*/
	/*}*/

	// TODO: Import code for reading out timestamps



	return 0;
}
