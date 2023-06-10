// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "version.h"
#include "tstest.h"

void tstest_help()
{
	fprintf(stderr, "\n");
	fprintf(stderr, "--- TSTest v%d.%d ---\n", tstest_VERSION_MAJOR, tstest_VERSION_MINOR);
	fprintf(stderr, "\nUsage:\n  tstest [mode] [options]\n\n");
	fprintf(stderr, "Modes:\n  pkt\n  extts\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{

	if (argc < 2) {
		tstest_help();
		return -EINVAL;
	}

	if (strcmp(argv[1], "pkt") == 0)
		return run_pkt_mode(argc-1, &argv[1]);
	else if (strcmp(argv[1], "extts") == 0)
		return run_extts_mode(argc-1, &argv[1]);

	tstest_help();
	return -EINVAL;
}
