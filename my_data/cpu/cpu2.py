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
from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY
# import argparse

# 定义变量
frequency = 99
interval = 99999999

# 初始化 BPF 程序
b = BPF(src_file="runqlen.c")
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency)

# dist = b.get_table("dist")


def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    print(event.len)
    # if start == 0:
    #         start = event.ts
    # time_s = (float(event.ts - start)) / 1000000000
    # print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
    #     "Hello, perf_output!"))

b["result"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()




# while(1):
# 	try:
# 		sleep(int(interval))
# 	except KeyboardInterrupt:
# 	 	exiting = 1

# 	print()
# 	# 空行打印时间戳
# 	print("%-8s\n" % strftime("%H:%M:%S"), end="")
# 	dist.print_linear_hist("runqlen", "cpu")
# 	dist.clear()

# 	if exiting == 1 :
# 		exit()


























