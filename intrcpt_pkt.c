#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>

typedef struct nfq_handle nfqsocket;
typedef struct nfq_q_handle qhandle;
#define __BYTE_ORDER __LITTLE_ENDIAN

/*
 * 初始化创建内核用户空间网络包通道 
 * 参数:
 *  queue_num: 创建队列号, 队列如果已经存在则失败则退出程序
 *  mode: 设置模式
 *  nc: 设置packet处理函数
 *  nsqsocket: nfqsocket
 *  qhdl: 队列handle 
 * 返回:
 *  socket fd
 */
int create_nfq_handle(uint16_t queue_num, uint8_t mode,
                      nfq_callback *nc, nfqsocket **nskt, qhandle **qhdl);

int create_nfq_handle(uint16_t queue_num, uint8_t mode,
                      nfq_callback *nc, nfqsocket **nskt, qhandle **qhdl)
{
    // nfq socket(nfq handler)
    nfqsocket *h;
    // nfq 队列handler
    qhandle *qh;
    // 队列号
    uint16_t queue_num;
    extern int errno;

    // open nfqueue handler, 对应为套接字fd
    h = nfq_open();
    if (!h)
    {
        fprintf(stderr, "nfq_open failed, error:%s", strerr(errno));
        exit(-1);
    }

    // 如果nfqueue handler之前绑定过AF_INET, 进行解除绑定
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "unbind nfq_handler to AF_INET failed, err: %s", strerr(errno));
        exit(-1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "start to bind nfq_handler AF_INET: err: %s", strerr(errno));
        exit(-1);
    }

    // 开始创建内核和用户空间通信队列,如果对应的queue_num已经存在,创建不成功,不影响之前的队列
    qh = nfq_create_queue(h, queue_num, nc, NULL);
    if (!qh)
    {
        fprintf(stderr, "error met during create queue, error:%s\n", strerr(errno));
        exit(-1);
    }

    // 设置要从队列中取得的packet的格式
    // 0xffff == 2**16-1(65535长度)的buffer
    if (nfq_set_mode(qh, mode, 0xffff))
    {
        fprintf(stderr, "set mode failed, err:%s", strerr(errno));
        exit(-1);
    }
    *nskt = h;
    *qhdl = qh;
    return nfq_fd(h);
}

// 对每一个从队列中收到的消息进行处理的函数
// 目前的方式是对 tcp payload 中的内容进行reverse
int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    unsigned char *rawData;
    int sendverdict;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    // 读取payload数据放入rawData中
    int len = nfq_tcp_get_payload(nfad, &rawData);
    /**
     * family: 选择使用哪个family
     * data: 指向哪个packet data
     * len: 包的长度,包含了ip header
     * extra: Extra memory in the tail to be allocated(for mangling)
     */
    struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    // try to reverse tcp data payload
    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    if (ip == NULL)
    {
        fprintf(stderr, "get ip header from pktBuffer failed, err:%s", strerr(errno));
        exit(-1);
    }
    // 读取tcp header之前要先调用此方法,否则不会分析tcp header
    if (nfq_ip_set_transport_header(pkBuff, ip) < 0)
    {
        fprintf(stderr, "get tcp header info failed!");
        exit(-1);
    }
    // 判断协议是否为TCP,并进行更改
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
        if (tcp == NULL)
        {
            fprintf(stderr, "invalid error:%s", strerr(errno));
            exit(-1);
        }
        // get payload of pkBuff
        char *payload = (char *)nfq_tcp_get_payload(tcp, pkBuff);
        int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
        // 考虑tcp length 的大小要乘以4倍
        payloadLen -= 4 * tcp->res1;

        // do reverse operation
        // 仅限于ascii码顺序的字符
        int i;
        for (i = 0; i < payloadLen / 2; i++)
        {
            char tmp = payload[i];
            payload[i] = payload[payloadLen - 1 - i];
            payload[payloadLen - 1 - i] = tmp;
        }
        // tcp payload 发生了变化, 需要重新计算checksum
        nfq_tcp_compute_checksum_ipv4(tcp, ip);
        // 发送sendVerdict
        sendverdict = nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
        // 记住释放pkbBuff
        pktb_free(pkBuff);
        return sendverdict;
    }
    // 发送原来的数据
    sendverdict = nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    // end 释放rawData
    pktb_free(pkBuff);
    return sendverdict;
}

int main()
{
    nfqsocket *h;
    qhandle *qh;
    uint16_t queue_num = 0;
    uint8_t mode = NFQNL_COPY_PACKET;
    char buf[4096];
    ssize_t rv;

    int fd = create_nfq_handle(queue_num, mode, callback, &h, &qh);
    while ((rv = recv(fd, buf, sizeof(buf), 0)))
    {
        printf("Has received a packet \n");
        if (nfq_handle_packet(h, buf, rv) < 0)
        {
            // 由callback执行对相应包的处理
            printf("handle packet failed! \n");
        }
    }
}