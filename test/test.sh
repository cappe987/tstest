#!/bin/bash

ip link add veth1 type veth peer name veth2
ip link set dev veth1 up
ip link set dev veth2 up

BIN=$1
TEST=$2

tests="delay_basic"

delay_basic() {
	$BIN delay server -i veth1 &
	PID=$!

	OUT=$($BIN delay client -i veth2 -c 1)
	kill $PID

	NUM=$(echo $OUT | cut -d' ' -f2)

	if ((NUM < 10000 && NUM > 0)); then
		return 0
	else
		echo "path delay > 10000. Value: $NUM"
		return 1
	fi
}

if [ "$TEST" = "" ]; then
	echo "[TEST] Running tests"
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
	echo "[TEST] Running test: $TEST"
	curr_test=$TEST
	if $test; then
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
