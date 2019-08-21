#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
/**
 * p: device handle
 * cnt: 抓包数量设置(0: 无限制数量抓包)
 * pcap_handler: 每抓到一个包执行这个方法
 * user: 回调方法传入的参数
 */
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);

int main(int argc, char *argv[])
{
    char *device_name = "lo";
    pcap_t *handle;
    // 关闭混淆模式
    int prmisc = 0;
    int timeout_limit = 1000;
    char error_buffer[PCAP_ERRBUF_SIZE];

    /**
     * device_name: 设备名称
     * BUFSIZE: 最大抓多少字节的包
     * prmisc: 将网卡设置为混淆模式
     * tm_out: 超时时间
     * error_buffer: 错误控制 
     */
    handle = pcap_open_live(device_name, 1028, prmisc,
                            timeout_limit, error_buffer);
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    // 返回值指向包的data, 但不需要由调用者释放,所以不保证data有效
    // 1.只抓取一个包
    printf("call pcap_next \n");
    packet = pcap_next(handle, &packet_header);
    if (packet == NULL)
    {
        printf("no packet can be focused! \n");
        return 2;
    }
    print_packet_info(packet, packet_header);

    printf("call pcap_loop \n");
    // 2.循环抓包
    // 100表示抓包的个数
    pcap_loop(handle, 10, my_packet_handler, NULL);
    // 看看如何抓取
    pcap_close(handle);
    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet caputure length is:%d \n", packet_header.caplen);
    printf("Packet total length %d \n", packet_header.len);
}

/**
 * 自己定义的包处理,获取三层包类型
 */
void my_packet_handler(
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
void data_payload_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
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
    
}
