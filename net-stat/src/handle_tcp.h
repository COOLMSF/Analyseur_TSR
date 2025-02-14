#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>

u_char* handle_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet,int verbosite);
int check_net_bandwidth(void);
int check_syn_flood(void);
