#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/**
 * 利用pcap_compile将表达式str转化为过滤程序
 * fp指向bpf_program结构
 */
extern int	pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize,
	    bpf_u_int32 netmask);
extern int pcap_setfilter(pcap_t *p, struct bpf_program *fp);

int main(void)
{
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *dev = "capuse";
    struct bpf_program filter;
    char filter_exp[] = "port 80";
    bpf_u_int32 subnet_mask, ip;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        printf("Could not open %s - %s \n", dev, error_buffer);
        return 1;
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
    {
    }
}