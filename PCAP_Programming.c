#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

/* Ethernet header */
typedef struct ethheader{
    u_char  ether_dhost[6]; /* 목적지 주소 */
    u_char  ether_shost[6]; /* 송신지 주소 */
    u_short ether_type; /* Protocol type 결정 */
}ethheader;

/* IP Header */
typedef struct ipheader{
    unsigned char      iph_ihl:4, //IP header length
                        iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                        iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address    
}ipheader;

/* TCP Header */
typedef struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
}tcpheader;

void print_Ethernet(const ethheader *eth){
	printf("Ehernet, src : (%02x:%02x:%02x:%02x:%02x:%02x) dst : (%02x:%02x:%02x:%02x:%02x:%02x)", 
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5], 
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
	eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("protocol type : (%#04x)\n", ntohs(eth->ether_type));
}

void print_Ip(const ipheader *ip){
	printf("%7s, Src: %s Dst: %s \n", "IP",inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
}

void print_tcp(const tcpheader *tcp){
	printf("%7s, Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u\n","TCP",tcp->tcp_sport, tcp->tcp_dport, tcp->tcp_seq, tcp->tcp_ack);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
	const ethheader *eth = (ethheader *) packet;
	const ipheader *ip = (ipheader *)(packet + sizeof(ethheader));
	const tcpheader *tcp= (tcpheader *)(packet + sizeof(ethheader) + sizeof(ipheader));
   	print_Ethernet(eth);
	print_Ip(ip);
	print_tcp(tcp);
	int tcp_header_size = TH_OFF(tcp) * 4;

    // Calculate tcp's real header size
    int payload_size = header->len - sizeof(ethheader) - sizeof(ipheader) - tcp_header_size;

    // define payload
    u_char *payload = (u_char *)(packet + sizeof(ethheader) + sizeof(ipheader) + tcp_header_size);

    // check if payload is HTTP
    if (payload_size >= 4 && memcmp(payload, "HTTP", 4) == 0) {
        // Print HTTP message
        printf(">>Message:<<\n");
        printf("%.*s\n", payload_size, payload);
    }
    puts("\n");
}


int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s5
    handle = pcap_open_live("enp0s5", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp)) {
        pcap_perror(handle, "Error;");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet,NULL);

    pcap_close(handle); // close the handle
    return 0;
}