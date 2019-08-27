#!/bin/sh

if [[ $# -eq 0 ]];then
       echo "Supply processids: a,b ; cgroup: xxx!"
       exit 1 
fi
sudo sh -c 'echo "" > /sys/fs/cgroup/net_cls/$2/tasks'
IFS=',' read -ra ADDR <<< "$1"
for i in "${ADDR[@]}"; do
  sudo sh -c "echo $i >> /sys/fs/cgroup/net_cls/$2/tasks"
done

