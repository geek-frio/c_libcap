#!/bin/sh
echo "create block cgroup for subsystem net_cls..."
sudo mkdir /sys/fs/cgroup/net_cls/block
echo "create classid in net_cls.classid"
sudo sh -c "echo $1 > /sys/fs/cgroup/net_cls/block/net_cls.classid"
echo "create iptables for NFQUEUE"
sudo iptables -D OUTPUT -m cgroup --cgroup $1 -p ip -j NFQUEUE --queue-num 0