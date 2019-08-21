#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        printf("err finding device:%s\n", error_buffer);
        return 1;
    }
    printf("Network device is:%s \n", device);

    /* 随机抽取一个获取设备的信息 */

    int lookup_return_code;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    lookup_return_code = pcap_lookupnet(device, &netp, &maskp, error_buffer);

    // if(lookup_return_code == -1) {
    //     printf("%s \n", error_buffer);
    //     return 1;
    // }

    /* 获取所有网络设备的信息  */
    pcap_if_t *alldevsp;
    /* 承载ip地址 */
    struct sockaddr *sockaddr;
    /* 获取所有设备并校验返回值 */
    lookup_return_code = pcap_findalldevs(&alldevsp, error_buffer);
    if (lookup_return_code == -1)
    {
        printf("%s \n", error_buffer);
        return 1;
    }
    /*遍历设备详细信息 */
    pcap_if_t *dev;
    for (dev = alldevsp; dev != NULL; dev = dev->next)
    {
        struct pcap_addr *dev_addr;
        for (dev_addr = dev->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
        {
            sockaddr = dev_addr->addr;
            // 注意这里的sa_family的获取,如果为AF_NET则进行强制转化
            if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask)
            {
                printf("device:%s \n", dev->name);
                printf("device flags is:%d \n", dev->flags);
                // 转化成internet address
                struct sockaddr_in *sa = (struct sockaddr_in *)dev_addr->addr;
                // mask 也要转化成internet address
                struct sockaddr_in *ma = (struct sockaddr_in *)dev_addr->netmask;
                // port信息存储
                uint32_t port;
                char addr[17];
                char mask[17];
                // 转化成可读port
                port = ntohl(sa->sin_port);
                // 转化成addr
                inet_ntop(sa->sin_family, &(sa->sin_addr), addr, sizeof(addr));
                inet_ntop(ma->sin_family, &(ma->sin_addr), mask, sizeof(mask));
                printf("port is:%d\naddr is:%s\nmask is:%s \n", port, addr, mask);
            }
        }
    }
}