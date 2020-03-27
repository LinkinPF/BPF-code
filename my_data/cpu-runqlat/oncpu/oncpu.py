#!/usr/bin/python
# -*- coding: utf-8 -*-
# @lint-avoid-python-3-compatibility-imports
#
# cpudist   Summarize on- and off-CPU time per task as a histogram.
#
# USAGE: cpudist [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends on or off the CPU, and shows this time
# as a histogram, optionally per-process.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse








b = BPF(src_file='untitled.c')
# print(bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="sched_switch")

print("Tracing on-CPU time... Hit Ctrl-C to end.")

# exiting = 0 if args.interval else 1
# dist = b.get_table("dist")
# while (1):
#     try:
#         sleep(int(args.interval))
#     except KeyboardInterrupt:
#         exiting = 1

#     print()
#     if args.timestamp:
#         print("%-8s\n" % strftime("%H:%M:%S"), end="")

#     def pid_to_comm(pid):
#         try:
#             comm = open("/proc/%d/comm" % pid, "r").read()
#             return "%d %s" % (pid, comm)
#         except IOError:
#             return str(pid)

#     dist.print_log2_hist(label, section, section_print_fn=pid_to_comm)
#     dist.clear()

#     countdown -= 1
#     if exiting or countdown == 0:
#         exit()

def print_event(cpu, data, size):
    global start
    event = b["result"].event(data)
    # 输出数据
    # f.write(strftime("%H:%M:%S") + " " + str(event.time) + '\r\n')
    # print("%-8s\n" % strftime("%H:%M:%S"))
    print(event.total_oncpu_time)

exiting = 0 
# f = open("/home/zcy/my_bcc/my_data/cpu-runqlat/data.csv",'w')
b["result"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exiting = 1
    if exiting == 1:
        # f.close()
        exit()