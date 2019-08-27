#!/bin/sh
if [[ $# -eq 0 ]];then
	echo "no arguments supplied,please give the cgroup class id and group directory !"
	return
fi
echo "create block cgroup for subsystem net_cls..."
sudo mkdir /sys/fs/cgroup/net_cls/$2
echo "create classid in net_cls.classid"
sudo sh -c "echo $1 > /sys/fs/cgroup/net_cls/$2/net_cls.classid"
echo "create iptables for NFQUEUE"
sudo iptables -D OUTPUT -m cgroup --cgroup $1 -p ip -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -m cgroup --cgroup $1 -p ip -j NFQUEUE --queue-num 0
