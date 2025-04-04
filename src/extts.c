// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>
//

#define _GNU_SOURCE

#include <linux/ptp_clock.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "net_tstamp_cpy.h"
#include "version.h"
#include "tstest.h"
#include "pkt.h"

typedef struct {
	char *iface;
	int polarity;
	int channel;
	int pin_idx;
} Extts_cfg;

typedef struct {
	char *iface;
	int pulsewidth;
	int channel;
	int pin_idx;
} Pps_cfg;

#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_emerg(...) fprintf(stderr, __VA_ARGS__)
#define pr_debug(...) fprintf(stderr, __VA_ARGS__)

#define CLOCK_INVALID -1
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd) ((clockid_t)((((unsigned int)~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk) ((unsigned int)~((clk) >> 3))
#define BITS_PER_LONG (sizeof(long) * 8)
#define MAX_PPB_32 32767999 /* 2^31 - 1 / 65.536 */

/*
 * Bits of the ptp_extts_request.flags field:
 */
#ifndef PTP_ENABLE_FEATURE
#define PTP_ENABLE_FEATURE (1 << 0)
#endif
#ifndef PTP_RISING_EDGE
#define PTP_RISING_EDGE (1 << 1)
#endif
#ifndef PTP_FALLING_EDGE
#define PTP_FALLING_EDGE (1 << 2)
#endif
#ifndef PTP_STRICT_FLAGS
#define PTP_STRICT_FLAGS (1 << 3)
#endif
#ifndef PTP_EXTTS_EDGES
#define PTP_EXTTS_EDGES (PTP_RISING_EDGE | PTP_FALLING_EDGE)
#endif

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

#ifdef PTP_PEROUT_REQUEST2
#define PTP_PEROUT_REQUEST_FAILED "PTP_PEROUT_REQUEST2 failed: %m"
#else
#define PTP_PEROUT_REQUEST_FAILED "PTP_PEROUT_REQUEST failed: %m"
#define PTP_PEROUT_REQUEST2 PTP_PEROUT_REQUEST
#endif

int running;

struct ts2phc_clock {
	clockid_t clkid;
	int fd;
	int phc_index;
	char *name;
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

void extts_help()
{
	fprintf(stderr, "\n--- TSTest External Timestamps ---\n\n");
	fprintf(stderr, "Enables EXTTS on the given interface and listens for events.\n\n\
Usage:\n\
        tstest extts [options]\n\n\
Options:\n\
        -i <interface>\n\
        -p <pin>\n\
        -c <channel>\n\
        -P <polarity> (rising|falling|both)\n\
\n");
}

void pps_help()
{
	fprintf(stderr, "\n--- TSTest External Timestamps ---\n\n");
	fprintf(stderr, "Enables PPS on the given interface. Disables and exits on SIGINT\n\n\
Usage:\n\
        tstest pps [options]\n\n\
Options:\n\
        -i <interface>\n\
        -p <pin>\n\
        -c <channel>\n\
        -w <pulsewidth>. Width of the PPS pulse in nanoseconds.\n\
\n");
}

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

/*int phc_has_writephase(clockid_t clkid)*/
/*{*/
/*struct ptp_clock_caps caps;*/

/*if (phc_get_caps(clkid, &caps)) {*/
/*return 0;*/
/*}*/
/*return caps.adjust_phase;*/
/*}*/

enum parser_result get_ranged_int(const char *str_val, int *result, int min, int max)
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
	ifr.ifr_data = (char *)&info;
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
			int r = get_ranged_int(phc_device_path + strlen("/dev/ptp"), phc_index, 0,
					       65535);
			if (r) {
				fprintf(stderr, "failed to parse PHC index from %s\n",
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
	snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d", ts_info.phc_index);
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
	clockid_t clkid;
	struct ts2phc_clock *c;
	int phc_index = -1;
	int err;

	clkid = posix_clock_open(device, &phc_index);
	if (clkid == CLOCK_INVALID)
		return NULL;

	c = calloc(1, sizeof(*c));
	if (!c) {
		pr_err("failed to allocate memory for a clock\n");
		return NULL;
	}
	c->clkid = clkid;
	c->fd = CLOCKID_TO_FD(clkid);
	c->phc_index = phc_index;
	err = asprintf(&c->name, "/dev/ptp%d", phc_index);
	if (err < 0) {
		free(c);
		posix_clock_close(clkid);
		return NULL;
	}

	/*LIST_INSERT_HEAD(&priv->clocks, c, list);*/
	return c;
}

static int toggle_extts(struct ts2phc_clock *clock, Extts_cfg *cfg, int ena)
{
	struct ptp_extts_request extts;
	struct ptp_pin_desc pin_desc;
	int err;

	memset(&extts, 0, sizeof(struct ptp_extts_request));
	memset(&pin_desc, 0, sizeof(pin_desc));
	pin_desc.chan = cfg->channel;
	pin_desc.index = cfg->pin_idx;
	pin_desc.func = PTP_PF_EXTTS;

	printf("index %d. chan %d. func %d\n", cfg->pin_idx, cfg->channel, PTP_PF_EXTTS);
	if (ena) {
		if (phc_number_pins(clock->clkid) > 0) {
			err = phc_pin_setfunc(clock->clkid, &pin_desc);
			if (err < 0) {
				pr_err("PTP_PIN_SETFUNC request failed");
				return -1;
			}
		}
	}

	extts.index = cfg->channel;
	extts.flags = cfg->polarity | (ena ? PTP_ENABLE_FEATURE : 0);
	err = ioctl(clock->fd, PTP_EXTTS_REQUEST2, &extts);
	if (err < 0) {
		pr_err(PTP_EXTTS_REQUEST_FAILED);
		return -1;
	}
	return 0;
}

static void pps_destroy(struct ts2phc_clock *clock, Pps_cfg *cfg)
{
	struct ptp_perout_request perout_request;

	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = cfg->channel;
	if (ioctl(clock->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
	}
}

static int toggle_pps(struct ts2phc_clock *clock, Pps_cfg *cfg, int ena)
{
	struct ptp_perout_request perout_request;
	struct ptp_pin_desc desc;
	int32_t perout_phase;
	int32_t pulsewidth;
	struct timespec ts;
	int err;

	if (!ena) {
		pps_destroy(clock, cfg);
		return 0;
	}

	memset(&desc, 0, sizeof(desc));

	desc.index = cfg->pin_idx;
	desc.func = PTP_PF_PEROUT;
	desc.chan = cfg->channel;

	if (phc_pin_setfunc(clock->clkid, &desc)) {
		pr_err("Failed to set the pin. Continuing bravely on...");
	}
	if (clock_gettime(clock->clkid, &ts)) {
		perror("clock_gettime");
		return -1;
	}
	/* perout_phase = config_get_int(cfg, dev, "ts2phc.perout_phase"); */
	perout_phase = 0;
	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = cfg->channel;
	perout_request.period.sec = 1;
	perout_request.period.nsec = 0;
	perout_request.flags = 0;
	pulsewidth = cfg->pulsewidth;
	if (pulsewidth) {
		perout_request.flags |= PTP_PEROUT_DUTY_CYCLE;
		perout_request.on.sec = pulsewidth / NS_PER_SEC;
		perout_request.on.nsec = pulsewidth % NS_PER_SEC;
	}
	if (perout_phase != -1) {
		perout_request.flags |= PTP_PEROUT_PHASE;
		perout_request.phase.sec = perout_phase / NS_PER_SEC;
		perout_request.phase.nsec = perout_phase % NS_PER_SEC;
	} else {
		perout_request.start.sec = ts.tv_sec + 2;
		perout_request.start.nsec = 0;
	}

	err = ioctl(clock->fd, PTP_PEROUT_REQUEST2, &perout_request);
	if (err) {
		/* Backwards compatibility with old ts2phc where the pulsewidth
		 * property would be just informative (a way to filter out
		 * events in the case that the PPS sink can only do extts on
		 * both rising and falling edges). There, nothing would be
		 * configured on the PHC PPS source towards achieving that
		 * pulsewidth. So in case the ioctl failed, try again with the
		 * DUTY_CYCLE flag unset, in an attempt to avoid a hard
		 * failure.
		 */
		perout_request.flags &= ~PTP_PEROUT_DUTY_CYCLE;
		memset(&perout_request.rsv, 0, 4 * sizeof(unsigned int));
		err = ioctl(clock->fd, PTP_PEROUT_REQUEST2, &perout_request);
	}
	if (err) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
		return err;
	}

	return 0;
}

void clock_destroy(struct ts2phc_clock *clock)
{
	posix_clock_close(clock->clkid);
	free(clock->name);
	free(clock);
}

static int clear_fifo(struct ts2phc_clock *clock)
{
	struct pollfd pfd = {
		.events = POLLIN | POLLPRI,
		.fd = clock->fd,
	};
	struct ptp_extts_event event;
	int cnt, size;

	while (1) {
		cnt = poll(&pfd, 1, 100);
		if (cnt < 0) {
			if (EINTR == errno) {
				continue;
			} else {
				pr_emerg("poll failed");
				return -1;
			}
		} else if (!cnt) {
			break;
		}
		size = read(pfd.fd, &event, sizeof(event));
		if (size != sizeof(event)) {
			pr_err("read failed");
			return -1;
		}
		printf("Clearing queue: %s extts index %u at %lld.%09u", clock->name, event.index,
		       event.t.sec, event.t.nsec);
	}

	return 0;
}

static int poll_events(struct ts2phc_clock *clock)
{
	struct pollfd pfd = {
		.events = POLLIN | POLLPRI,
		.fd = clock->fd,
	};
	struct ptp_extts_event event;
	int cnt, size;

	while (running) {
		cnt = poll(&pfd, 1, 2000);
		if (cnt < 0) {
			if (EINTR == errno) {
				break;
			} else {
				pr_emerg("poll failed");
				return -1;
			}
		} else if (!cnt) {
			continue;
		}
		size = read(pfd.fd, &event, sizeof(event));
		if (size != sizeof(event)) {
			pr_err("read failed");
			return -1;
		}
		printf("%s extts index %u at %lld.%09u\n", clock->name, event.index, event.t.sec,
		       event.t.nsec);
	}

	return 0;
}

static void sig_handler(int sig)
{
	running = 0;
}

static int parse_edge_type(char *str)
{
	if (strcmp(str, "rising") == 0)
		return PTP_RISING_EDGE;
	else if (strcmp(str, "falling") == 0)
		return PTP_FALLING_EDGE;
	else if (strcmp(str, "both") == 0)
		return PTP_EXTTS_EDGES;
	else
		return -1;
}

static int parse_args_extts(int argc, char **argv, Extts_cfg *cfg)
{
	int opt_index;
	int c;

	if (argc == 1) {
		extts_help();
		return EINVAL;
	}

	struct option long_options[] = {
		{ "iface", no_argument, NULL, 'i' },   { "pin", no_argument, NULL, 'p' },
		{ "channel", no_argument, NULL, 'c' }, { "polarity", no_argument, NULL, 'P' },
		{ "help", no_argument, NULL, 'h' },    { NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "i:p:c:P:h", long_options, &opt_index)) != -1) {
		switch (c) {
		case 'i':
			cfg->iface = optarg;
			break;
		case 'p':
			cfg->pin_idx = atoi(optarg);
			break;
		case 'c':
			cfg->channel = atoi(optarg);
			break;
		case 'P':
			cfg->polarity = parse_edge_type(optarg);
			break;
		case 'h':
			extts_help();
			exit(0);
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EINVAL;
		default:
			extts_help();
			exit(0);
		}
	}

	if (!cfg->iface) {
		fprintf(stderr, "No interface provided\n");
		return EINVAL;
	}
	if (cfg->pin_idx < 0) {
		fprintf(stderr, "Invalid pin index\n");
		return EINVAL;
	}
	if (cfg->channel < 0) {
		fprintf(stderr, "Invalid channel\n");
		return EINVAL;
	}
	if (cfg->polarity < 0) {
		fprintf(stderr, "Invalid polarity type\n");
		return EINVAL;
	}

	return 0;
}

int run_extts_mode(int argc, char **argv)
{
	struct ptp_extts_request extts;
	struct ts2phc_clock *clock;
	Extts_cfg cfg = { 0 };
	int chan, polarity;
	int err = 0;

	cfg.iface = NULL;
	cfg.channel = 0;
	cfg.pin_idx = 0;
	cfg.polarity = PTP_RISING_EDGE;

	err = parse_args_extts(argc, argv, &cfg);
	if (err)
		return err;

	clock = ts2phc_clock_add(cfg.iface);

	if (!clock)
		return -EINVAL;

	err = toggle_extts(clock, &cfg, 1);
	if (err)
		goto out_destroy_clock;

	running = 1;

	/* signal(SIGINT, sig_handler); */
	handle_term_signals();

	clear_fifo(clock);
	poll_events(clock);

	err = toggle_extts(clock, &cfg, 0);
	if (err)
		pr_err("failed to disable extts\n");

out_destroy_clock:
	clock_destroy(clock);

	return err;
}

static int parse_args_pps(int argc, char **argv, Pps_cfg *cfg)
{
	int opt_index;
	int c;

	if (argc == 1) {
		pps_help();
		return EINVAL;
	}

	struct option long_options[] = {
		{ "iface", no_argument, NULL, 'i' },   { "pin", no_argument, NULL, 'p' },
		{ "channel", no_argument, NULL, 'c' }, { "pulsewidth", no_argument, NULL, 'w' },
		{ "help", no_argument, NULL, 'h' },    { NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "i:p:c:w:h", long_options, &opt_index)) != -1) {
		switch (c) {
		case 'i':
			cfg->iface = optarg;
			break;
		case 'p':
			cfg->pin_idx = atoi(optarg);
			break;
		case 'c':
			cfg->channel = atoi(optarg);
			break;
		case 'w':
			cfg->pulsewidth = atoi(optarg);
			break;
		case 'h':
			pps_help();
			exit(0);
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return EINVAL;
		default:
			pps_help();
			exit(0);
		}
	}

	if (!cfg->iface) {
		fprintf(stderr, "No interface provided\n");
		return EINVAL;
	}
	if (cfg->pin_idx < 0) {
		fprintf(stderr, "Invalid pin index\n");
		return EINVAL;
	}
	if (cfg->channel < 0) {
		fprintf(stderr, "Invalid channel\n");
		return EINVAL;
	}
	if (cfg->pulsewidth < 0 || cfg->pulsewidth > NS_PER_SEC) {
		fprintf(stderr, "Invalid pulse width type\n");
		return EINVAL;
	}

	return 0;
}

int run_pps_mode(int argc, char **argv)
{
	struct ptp_extts_request extts;
	struct ts2phc_clock *clock;
	Pps_cfg cfg = { 0 };
	int chan, polarity;
	int err = 0;

	cfg.iface = NULL;
	cfg.channel = 0;
	cfg.pin_idx = 0;
	cfg.pulsewidth = 100000000;
	/* cfg.polarity = PTP_RISING_EDGE; */

	err = parse_args_pps(argc, argv, &cfg);
	if (err)
		return err;

	clock = ts2phc_clock_add(cfg.iface);

	if (!clock)
		return -EINVAL;

	err = toggle_pps(clock, &cfg, 1);
	if (err)
		goto out_destroy_clock;

	running = 1;

	/* signal(SIGINT, sig_handler); */
	handle_term_signals();

	// TODO: Use sigwait instead
	while (running) {
		usleep(1000 * 100);
	}

	err = toggle_pps(clock, &cfg, 0);
	if (err)
		pr_err("failed to disable pps\n");

out_destroy_clock:
	clock_destroy(clock);

	return err;
}
