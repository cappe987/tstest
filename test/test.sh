#!/bin/bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>

tstest=$1
TEST=$2

delay_single() {
	$tstest delay server -S -i veth1 &
	PID=$!

	sleep 0.5

	OUT=$($tstest delay client -S -i veth2 -c 1)
	kill $PID

	NUM=$(echo $OUT | cut -d' ' -f2)

	if [ -z "$NUM" ]; then
		echo "Bad output: $OUT"
		return 1
	elif ((NUM >= 10000 || NUM <= 0)); then
		echo "Bad path delay. Value: $NUM"
		return 1
	fi

	return 0
}

delay_1_5_step_fail() {
	# Redirect warnings to /dev/null since this is a test that should fail.
	# But this keeps the output clean.
	$tstest delay server -S -i veth1 --1.5step 2>/dev/null &
	PID=$!

	sleep 0.5

	OUT=$($tstest delay client -S -i veth2 -c 1)
	kill $PID

	NUM=$(echo $OUT | cut -d' ' -f2)

	if [ -z "$NUM" ]; then
		echo "Bad output: $OUT"
		return 1
	elif ((NUM < 10000 && NUM > 0)); then
		echo "Path delay value: $NUM"
		echo "1.5-step is expected to fail in software"
		return 1
	fi

	return 0
}

delay_timeout() {
	TMP=$(mktemp)
	OUT=$($tstest delay client -S -i veth2 -c 1 2> $TMP)
	if cat "$TMP" | grep -q 'timed out waiting for pdelay_resp'; then
		return 0
	else
		echo "Unexpected output: $OUT"
		return 1
	fi

	rm "$TMP"
}

tests="delay_single delay_1_5_step_fail delay_timeout"


echo "[TEST] Setting up tests"
ip link add veth1 type veth peer name veth2
ip link set dev veth1 up
ip link set dev veth2 up

# Allow interfaces to come up
sleep 3

echo "[TEST] Running tests"
if [ "$TEST" = "" ]; then
	for t in $tests; do
		curr_test=$t
		if $t; then
			echo -e "[\e[32mPASS\e[0m] $t"
		else
			echo -e "[\e[31mFAIL\e[0m] $t"
			failed=1
		fi
	done
elif echo "$tests" | grep -q "$TEST"; then
	curr_test=$TEST
	if $TEST; then
		echo -e "[\e[32mPASS\e[0m] $t"
	else
		echo -e "[\e[31mFAIL\e[0m] $t"
		failed=1
	fi
else
	echo "Test does not exist..."
	exit 1
fi

ip link del dev veth1

exit $failed
