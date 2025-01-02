# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Casper Andersson <casper.casan@gmail.com>
#!/bin/bash

metric=$1
input=$2
output=$3

if [ -z "$metric" ]; then
	echo -e "Usage:\n    plot.sh <metric> <input-file> <output-file>"
	exit 1
fi
if [ -z "$input" ]; then
	echo -e "Usage:\n    plot.sh <metric> <input-file> <output-file>"
	exit 1
fi
if [ -z "$output" ]; then
	echo -e "Usage:\n    plot.sh <metric> <input-file> <output-file>"
	exit 1
fi

gnuplot <<-EOFMarker
	set format y '%0.f'
	# set yrange [0:*]
	set xlabel 'Elapsed Time [s]'
	set ylabel '$metric [ns]'
	set grid ytics
	set grid xtics
	# set grid mxtics
	set xtics nomirror
	set ytics nomirror
	set autoscale xfix
	# unset key
	# set key autotitle columnheader
	#set style line 1 lc rgb '#E41A1C' pt 1 ps 1 lt 1 lw 2 # red
	# set terminal pdfcairo enhanced color dashed font 'Arial, 14' rounded size 16 cm, 9.6 cm
	set grid lt 1 lc rgb '#e6e6e6' #'grey'
	set terminal pdfcairo rounded size 16 cm, 9.6 cm
	set output '$output'
	plot '$input' title '$metric' with lines ls 1
EOFMarker
	#set term svg
	#set term png
