#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

int main(){
    char *device_name = "capuse";
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
    // handle = pcap_open_live(device_name, 1028, prmisc,
    //                         timeout_limit, error_buffer);
    
    // 在启动之前先设置对应的混淆或者监控模式
    /**
     * 对于无线的混淆模式可以设置Monitor
     * 对于有线/无线同时设置混淆模式可以设置promiscuous
     * 
     * pcap_open_live同时创建和启动
     * 可以改成:
     * pcap_create先创建
     * 设置相关模式
     * pcap_activate激活
     * 
     * 这也是初始化的好路子,每项设置都很清晰明白
     */
    pcap_t *handle =pcap_create(device_name, error_buffer);
    pcap_set_rfmon(handle, 1);
    pcap_set_promisc(handle, 1);
    // 设置抓包的长度
    pcap_set_snaplen(handle, 2048);
    pcap_set_timeout(handle, 1000);

    pcap_activate(handle);

}