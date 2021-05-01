#include <netinet/in.h>
typedef struct info {
	int sport, dport;
	in_addr_t src_ip, dst_ip;
} Info;
