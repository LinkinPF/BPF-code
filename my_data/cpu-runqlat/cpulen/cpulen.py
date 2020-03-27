#!/usr/bin/python
# -*- coding: utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# runqlen    Summarize scheduler run queue length as a histogram.
#            For Linux, uses BCC, eBPF.
#
# This counts the length of the run queue, excluding the currently running
# thread, and shows it as a histogram.
#
# Also answers run queue occupancy.
#
# USAGE: runqlen [-h] [-T] [-Q] [-m] [-D] [interval] [count]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support). Under tools/old is
# a version of this tool that may work on Linux 4.6 - 4.8.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 12-Dec-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig
from time import sleep, strftime
# from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY
import argparse

# arguments
examples = """examples:
    ./runqlen            # summarize run queue length as a histogram
    ./runqlen 1 10       # print 1 second summaries, 10 times
    ./runqlen -T 1       # 1s summaries and timestamps
    ./runqlen -O         # report run queue occupancy
    ./runqlen -C         # show each CPU separately
"""
parser = argparse.ArgumentParser(
    description="Summarize scheduler run queue length as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-O", "--runqocc", action="store_true",
    help="report run queue occupancy")
parser.add_argument("-C", "--cpus", action="store_true",
    help="print output for each CPU separately")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
frequency = 99





# initialize BPF & perf_events
b = BPF(src_file='bpf-cpulen.c')
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)

print("Sampling run queue length... Hit Ctrl-C to end.")



# ---------------------------------------------------------------------------

def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    # 输出数据
    # f.write(strftime("%H:%M:%S") + " " + str(event.time) + '\r\n')
    # print("%-8s\n" % strftime("%H:%M:%S"))
    print(event.total_len)




# output
exiting = 0
b["result"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		exiting = 1
	if exiting == 1:
		# f.close()
		exit()
# dist = b.get_table("dist")
# while (1):
#     try:
#         # sleep(int(args.interval))
#         sleep(1)
#     except KeyboardInterrupt:
#         exiting = 1

#     print()
#     # if args.timestamp:

#     print("%-8s\n" % strftime("%H:%M:%S"), end="")

    
#     # run queue length histograms
#     dist.print_linear_hist("runqlen", "cpu")
#     dist.clear()

#     countdown -= 1
#     if exiting or countdown == 0:
#         exit()
