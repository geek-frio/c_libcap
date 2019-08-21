#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

int main(){
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("test.cap", error_buffer);
    // do like live_capture
}