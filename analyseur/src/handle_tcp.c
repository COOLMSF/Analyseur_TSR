#include "handle_tcp.h"
#include "handle_ip.h"
#include "handle_ether.h"
#include "handle_http.h"
#include "handle_telnet.h"
#include "handle_dns.h"
#include "handle_smtp.h"
#include "handle_ftp.h"
#include "handle_pop.h"
#include "handle_imap.h"
#include "appli.h"
#include "csv.h"
#include <string.h>
#include <time.h>

void write_csv(FILE *fp, struct csv_data csv)
{
	char buf[MAX_LINE];

	sprintf(buf, "%s, %s, %s, %d, %d, %s, %d", \
		csv.time, csv.dst_ip, csv.src_ip, csv.dst_port, csv.src_port, \
		csv.protocol, csv.ip_ver);
	fwrite(buf, strlen(buf), 1, fp);
}

/* Function handling tcp packets  */
u_char* handle_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite) {
    const struct tcphdr* tcp;
	/* Why not iphdr? */
	const struct ip* ip;
    u_int length = pkthdr->len;

	/* write struct to file */
	FILE *fp;
	struct csv_data csv;

	/*
	 * We should write the field name when the program firstly runs
	 */
	if(access("data.csv", F_OK) != 0) {
	}

	/* append csv file */
	fp = fopen("data.csv", "a+");

    /* jump past the ethernet and ip headers */
	ip = (struct ip*)(packet + sizeof(struct ether_header));
    tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    length = length - sizeof(struct ether_header) - sizeof(struct ip);
    /* check that the remaining packet size is enough */
    if (length < sizeof(struct tcphdr)) {
        printf("\t\ttruncated tcp\n");
    }
	
	// save time
	time_t raw_time;
	struct tm *time_info;

	time(&raw_time);
	time_info = localtime(&raw_time);
	strcpy(csv.time, asctime(time_info));

	// save ip
	strcpy(csv.src_ip, inet_ntoa(ip->ip_src));
	strcpy(csv.dst_ip, inet_ntoa(ip->ip_dst));

	// save protocol
    if(ip->ip_p == 0x06){
        strcpy(csv.protocol, "TCP");
    }
    else if(ip->ip_p == 0x11){
		strcpy(csv.protocol, "UDP");
    }
    else if(ip->ip_p == 0x01){
		strcpy(csv.protocol, "ICMP");
    }
    else if(ip->ip_p == 0x02){
		strcpy(csv.protocol, "IGMP");
    }

	// save ip version
	csv.ip_ver = ip->ip_v;

	// save port
	csv.src_port = tcp->th_sport;
	csv.dst_port = tcp->th_dport;

	// write to file
	write_csv(fp, csv);
	fclose(fp);

    /* Depending on the verbosity we print the packet differently */
    switch (verbosite)
    {
        case 3:
            printf("\t\t----\n");
            printf("\t\tTCP\n");
            printf("\t\tPort source : %hu\n",ntohs(tcp->th_sport));
            printf("\t\tPort destination : %hu\n",ntohs(tcp->th_dport));
            printf("\t\tSequence Number : ");
            printf("%d\n",ntohl(tcp->th_seq));
            printf("\t\tAcknowledgment Number : ");
            printf("%d\n",ntohl(tcp->th_ack));
            printf("\t\tOffset : %d\n",tcp->th_off);

            printf("\t\tMessage type : ");
            if (tcp->th_flags & TH_URG) {
                printf("URG ");
            }
            if (tcp->th_flags & TH_ACK) {
                printf("ACK ");
            }
            if (tcp->th_flags & TH_PUSH) {
                printf("PUSH ");
            }
            if (tcp->th_flags & TH_RST) {
                printf("RST ");
            }
            if (tcp->th_flags & TH_SYN) {
                printf("SYN ");
            }
            if (tcp->th_flags & TH_FIN) {
                printf("FIN ");
            }
            printf("\t\t\n");

            printf("\t\tWindow size : %d\n",ntohs(tcp->th_win));
            printf("\t\tChecksum : %d\n",ntohs(tcp->th_sum));
            printf("\t\tUrgent pointer : %hu\n",tcp->th_urp);
            break;
        case 2:
            printf("\t\t(TCP) PSource : %hu  PDestination : %hu  Seq num : %d  Ack num : %d\n",
                tcp->th_sport,tcp->th_dport,tcp->th_seq,tcp->th_ack);
            break;
        case 1:
            printf(" | (TCP) PS : %hu  PD : %hu  SN : %d",
                tcp->th_sport,tcp->th_dport,tcp->th_seq);
            break;
        default:
            break;
    }

    /* We check what kind of packet is beneath the tcp header */
    if  (((ntohs(tcp->th_dport) == 80) || (ntohs(tcp->th_sport) == 80)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_HTTP(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 23) || (ntohs(tcp->th_sport) == 23)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_TELNET(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 53) || (ntohs(tcp->th_sport) == 53)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_DNS(args,pkthdr,packet,verbosite,1);
    }else if (((ntohs(tcp->th_dport) == 25) || (ntohs(tcp->th_sport) == 25)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_SMTP(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 587) || (ntohs(tcp->th_sport) == 587)) && (length - sizeof(struct tcphdr) > 0)) {
        printf(" (Ciphered SMTP)\n");
    }else if (((ntohs(tcp->th_dport) == 465) || (ntohs(tcp->th_sport) == 465)) && (length - sizeof(struct tcphdr) > 0)) {
        printf(" (SMTP with SSL)\n");
    }else if (((ntohs(tcp->th_dport) == 20) || (ntohs(tcp->th_sport) == 20)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_FTP(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 21) || (ntohs(tcp->th_sport) == 21)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_FTP(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 143) || (ntohs(tcp->th_sport) == 143)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_IMAP(args,pkthdr,packet,verbosite);
    }else if (((ntohs(tcp->th_dport) == 110) || (ntohs(tcp->th_sport) == 110)) && (length - sizeof(struct tcphdr) > 0)) {
        handle_POP(args,pkthdr,packet,verbosite);
    }
    return NULL;
}


