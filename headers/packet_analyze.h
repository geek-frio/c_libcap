#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_type(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void header_payload_anly_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet);
