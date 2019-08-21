#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <headers/find_device.h>
/**
 * 利用pcap_compile将表达式str转化为过滤程序
 * fp指向bpf_program结构
 */
extern int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize,
                        bpf_u_int32 netmask);
extern int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
extern int get_dev_ip4_netmask(char *dev, bpf_u_int32 *ip, bpf_u_int32 *mask);

int main(void)
{
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *dev = "capuse";

    // 获取网卡的ip和mask信息
    bpf_u_int32 ip;
    bpf_u_int32 mask;
    get_dev_ip4_netmask(dev, &ip, &mask);

    // 打开并激活抓包,支持最大包 8192, 非混杂模式, 超时1s
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, error_buffer);
    if (handle == NULL)
    {
        printf("Could not open %s - %s \n", dev, error_buffer);
        return 1;
    }
    // 生成规则program
    struct bpf_program filter;
    char filter_exp[] = "port 9090";
    bpf_u_int32 subnet_mask, ip;
    if (pcap_compile(handle, &filter, filter_exp, 0, mask) == -1)
    {
        printf("bad filter");
        return -1;
    }
    // 设置filter生效
    if(pcap_setfilter(handle, &filter) == -1){
        printf("set filter failed, %s \n", pcap_geterr(handle));
        return -1;
    }
    return 0;
}