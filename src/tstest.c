// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "tstest.h"

int main(int argc, char **argv)
{

	if (argc < 2) {
		fprintf(stderr, "Too few arguments\n");
		return -EINVAL;
	}

	if (strcmp(argv[1], "pkt") == 0)
		return run_pkt_mode(argc-1, &argv[1]);
	else if (strcmp(argv[1], "extts") == 0)
		return run_extts_mode(argc-1, &argv[1]);





	return 0;
}
