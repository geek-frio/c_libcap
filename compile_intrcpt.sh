#!/bin/bash
gcc intrcpt_pkt.c -lnfnetlink -lnetfilter_queue  -lpthread -L/usr/lib/x86_64-linux-gnu/ -l:libmnl.so
