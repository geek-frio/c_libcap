#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/**
 * 利用pcap_compile将表达式str转化为过滤程序
 * fp指向bpf_program结构
 */
extern int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize,
                        bpf_u_int32 netmask);
extern int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
extern int get_dev_ip4_netmask(char *dev, bpf_u_int32 *ip, bpf_u_int32 *mask);