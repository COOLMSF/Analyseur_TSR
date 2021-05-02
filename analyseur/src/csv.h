#define MAX_LINE 50
struct csv_data {
	char time[MAX_LINE];
	char dst_ip[MAX_LINE];
	char src_ip[MAX_LINE];
	unsigned dst_port;
	unsigned src_port;
	char protocol[5];
	short ip_ver;
};
