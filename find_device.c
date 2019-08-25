#include <headers/find_device.h>
#include <string.h>
#include <stdio.h>

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
    for (device = alldevsp; device != NULL; device = device->next)
    {
        if (strcmp(device->name, dev))
        {
            continue;
        }
        printf("device name is:%s\n", device->name);
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