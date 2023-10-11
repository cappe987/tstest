// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "version.h"
#include "tstest.h"

int tstest_version()
{
	fprintf(stderr, "TSTest v%d.%d\n", tstest_VERSION_MAJOR, tstest_VERSION_MINOR);
	return EINVAL;
}

int tstest_help()
{
	fprintf(stderr, "\n");
	fprintf(stderr, "--- TSTest v%d.%d ---\n", tstest_VERSION_MAJOR, tstest_VERSION_MINOR);
	fprintf(stderr, "\nUsage:\n\ttstest [mode]\n\n");
	fprintf(stderr, "Modes:\n\
	pkt - Send individual PTP packets\n\
	extts - Listen to EXTTS events\n\
	delay - Perform path delay measurements\n\
	version - Show version\n");
	fprintf(stderr, "\n");
	return EINVAL;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		tstest_help();
		return -EINVAL;
	}

	if (strcmp(argv[1], "pkt") == 0)
		return run_pkt_mode(argc - 1, &argv[1]);
	else if (strcmp(argv[1], "extts") == 0)
		return run_extts_mode(argc - 1, &argv[1]);
	else if (strcmp(argv[1], "delay") == 0)
		return run_delay_mode(argc - 1, &argv[1]);
	else if (strcmp(argv[1], "version") == 0)
		return tstest_version();
	else
		return tstest_help();
}
