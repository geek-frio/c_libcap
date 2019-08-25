#include <headers/packet_analyze.h>

static void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

/**
 * p: device handle
 * cnt: 抓包数量设置(0: 无限制数量抓包)
 * pcap_handler: 每抓到一个包执行这个方法
 * user: 回调方法传入的参数
 */
extern int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);

static void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet caputure length is:%d \n", packet_header.caplen);
    printf("Packet total length %d \n", packet_header.len);
}

/**
 * 自己定义的包处理,获取三层包类型
 */
void print_packet_type(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    // link packet header
    struct ether_header *eth_header;
    // 所有的ethernet header都是一样的长度
    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        printf("IP \n");
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
        printf("ARP \n");
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP)
    {
        printf("Reverse ARP\n");
    }
    print_packet_info(packet, *header);
}

/**
 * 读取运输层包payload数据
 */
void header_payload_anly_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    printf("handler is called!\n");
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        printf("not ip packet,skip...");
        return;
    }

    //注意caplen和len的区别
    // caplen: 真正抓取到的长度,受限于前面设置的抓取最大长度
    // len: 包整个的真正长度
    printf("total packet available:%d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes \n", header->len);

    int ethernet_header_length = 14;
    /*各种头部指针定义 */
    // ip 指针
    const u_char *ip_header;
    // tcp 指针
    const u_char *tcp_header;
    // payload 指针
    const u_char *payload;

    /* 各种头部长度 */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    // ip_header长度为ip header第一个字节的后四位
    ip_header_length = ((*ip_header) & 0x0F);
    // ip包的长度要放大4倍
    ip_header_length = ip_header_length << 2;
    printf("ip header length is:%d\n", ip_header_length);
    // 再往后走9个字节就可以获取Ip中运载的协议类型字段
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP)
    {
        printf("packet is not tcp packet, protocol:%d,so skip \n", protocol);
        return;
    }

    /* 进入tcp分析章节 */
    tcp_header = ip_header + ip_header_length;
    /* tcp header中的第12个字节, 前4个字节存储大小,所有要右移4位, 大小最终还要乘以4倍 */
    tcp_header_length = (*(tcp_header + 12) & 0xF0) >> 4 << 2;
    printf("tcp header length is bytes:%d \n", tcp_header_length);

    int total_header_len = ethernet_header_length + ip_header_length + tcp_header_length;
    printf("all the header length is ethernet frame is:%d \n", total_header_len);

    payload_length = header->caplen - total_header_len;
    printf("payload size is:%d \n", payload_length);

    payload = packet + total_header_len;
    printf("Memory address where payload begins:%p \n", payload);

    if (payload_length > 0)
    {
        const u_char *temp_pointer = payload;
        int i;
        for (i = 0; i < payload_length; i++)
        {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
    }
    return;
}
