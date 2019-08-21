#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/**
 * 根据device name 获取ip和mask信息
 * 如果调用失败,返回-1
 */
int get_dev_ip4_netmask(char *dev, bpf_u_int32 *ip, bpf_u_int32 *mask);

/**
 * 获取任意设备的ip和mask信息
 * 如果调用失败,返回-1
 */
int rand_get_dev_ip4_netmask(bpf_u_int32 *ip, bpf_u_int32 *mask);