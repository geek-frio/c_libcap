#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <headers/find_device.h>

int get_dev_ip4_netmask(char *dev, bpf_u_int32 *ip, bpf_u_int32 *mask)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    int lookup_return_code;

    pcap_if_t *alldevsp;
    lookup_return_code = pcap_findalldevs(&alldevsp, error_buffer);
    if (lookup_return_code == -1)
    {
        fprintf(stderr, "find all devs info failed!");
        return -1;
    }

    // 临时变量放置链表的element
    pcap_if_t *device;
    for (device = alldevsp; dev != NULL; device = device->next)
    {
        struct pcap_addr *addresses;
        // 获取接口对应的ip地址,会有多种的情况,比如ipv4和ipv6
        for (addresses = device->addresses; addresses != NULL; addresses = addresses->next)
        {
            // 判断是ipv4的情况才会进行获取
            if (addresses->addr->sa_family == AF_INET && addresses->addr && addresses->netmask)
            {
                int port;
                struct sockaddr_in *ip4_addr = (struct sockaddr_in *)addresses->addr;
                struct sockaddr_in *netmask4_addr = (struct sockaddr_in *)addresses->netmask;
                *ip = ip4_addr->sin_addr.s_addr;
                *mask = netmask4_addr->sin_addr.s_addr;

                // print human readable info for debug
                char addr[17];
                char mask[17];
                // 转化成可读port
                port = ntohl(ip4_addr->sin_port);
                // 转化成addr
                inet_ntop(ip4_addr->sin_family, &(ip4_addr->sin_addr), addr, sizeof(addr));
                inet_ntop(netmask4_addr->sin_family, &(netmask4_addr->sin_addr), mask, sizeof(mask));
                printf("port is:%d\naddr is:%s\nmask is:%s \n", port, addr, mask);
                return 0;
            }
        }
    }
    fprintf(stderr, "device don't have ip address");
    return -1;
}

int rand_get_dev_ip4_netmask(bpf_u_int32 *ip, bpf_u_int32 *mask)
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];

    int lookup_return_code;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        fprintf(stderr, "err finding device:%s\n", error_buffer);
        return -1;
    }

    lookup_return_code = pcap_lookupnet(device, ip, mask, error_buffer);
    if (lookup_return_code == -1)
    {
        fprintf(stderr, "%s \n", error_buffer);
    }
    return 0;
}

// int main(int argc, char **argv)
// {
//     char *dev = "capuse";
//     bpf_u_int32 ip;
//     bpf_u_int32 mask;

//     get_dev_ip4_netmask(dev, &ip, &mask);
//     // char *device;
//     // char error_buffer[PCAP_ERRBUF_SIZE];

//     // device = pcap_lookupdev(error_buffer);
//     // if (device == NULL)
//     // {
//     //     printf("err finding device:%s\n", error_buffer);
//     //     return 1;
//     // }
//     // printf("Network device is:%s \n", device);

//     // /* 随机抽取一个获取设备的信息 */

//     // int lookup_return_code;
//     // bpf_u_int32 netp;
//     // bpf_u_int32 maskp;
//     // lookup_return_code = pcap_lookupnet(device, &netp, &maskp, error_buffer);

//     // if (lookup_return_code == -1)
//     // {
//     //     printf("%s \n", error_buffer);
//     // }

//     // /* 获取所有网络设备的信息  */
//     // pcap_if_t *alldevsp;
//     // /* 承载ip地址 */
//     // struct sockaddr *sockaddr;
//     // /* 获取所有设备并校验返回值 */
//     // lookup_return_code = pcap_findalldevs(&alldevsp, error_buffer);
//     // if (lookup_return_code == -1)
//     // {
//     //     printf("%s \n", error_buffer);
//     //     return 1;
//     // }
//     // /*遍历设备详细信息 */
//     // pcap_if_t *dev;
//     // for (dev = alldevsp; dev != NULL; dev = dev->next)
//     // {
//     //     struct pcap_addr *dev_addr;
//     //     for (dev_addr = dev->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
//     //     {
//     //         sockaddr = dev_addr->addr;
//     //         // 注意这里的sa_family的获取,如果为AF_NET则进行强制转化
//     //         if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr && dev_addr->netmask)
//     //         {
//     //             printf("device:%s \n", dev->name);
//     //             printf("device flags is:%d \n", dev->flags);
//     //             // 转化成internet address
//     //             struct sockaddr_in *sa = (struct sockaddr_in *)dev_addr->addr;
//     //             // mask 也要转化成internet address
//     //             struct sockaddr_in *ma = (struct sockaddr_in *)dev_addr->netmask;
//     //             // port信息存储
//     //             uint32_t port;
//     //             char addr[17];
//     //             char mask[17];
//     //             // 转化成可读port
//     //             port = ntohl(sa->sin_port);
//     //             // 转化成addr
//     //             inet_ntop(sa->sin_family, &(sa->sin_addr), addr, sizeof(addr));
//     //             inet_ntop(ma->sin_family, &(ma->sin_addr), mask, sizeof(mask));
//     //             printf("port is:%d\naddr is:%s\nmask is:%s \n", port, addr, mask);
//     //         }
//     //     }
//     // }
// }