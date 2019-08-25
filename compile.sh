#!/bin/bash
gcc -I ./ cap_filter.c find_device.c live_capture.c -lpcap
