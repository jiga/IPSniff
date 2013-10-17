/* 
 * filter.h - filter datatypes and functions
 */

/* pre-processed offsets for filtering */

#define FILTER_ETH_SMAC		0
#define ETH_SMAC_LEN		6
#define FILTER_ETH_DMAC		6
#define ETH_DMAC_LEN		6
#define FILTER_ETH_PROTO	12
#define ETH_PROTO_LEN		2
#define FILTER_IP_PROTO		23
#define IP_PROTO_LEN		1
#define FILTER_IP_SIP		26
#define IP_SIP_LEN		4
#define FILTER_IP_DIP		30
#define IP_DIP_LEN		4
#define FILTER_TCP_SPORT	34
#define TCP_SPORT_LEN		2
#define FILTER_TCP_DPORT	36
#define TCP_DPORT_LEN		2
#define FILTER_UDP_SPORT	34
#define UDP_SPORT_LEN		2
#define FILTER_UDP_DPORT	36
#define UDP_DPORT_LEN		2
#define FILTER_ICMP_TYPE	34
#define ICMP_TYPE_LEN		1
#define FILTER_ICMP_CODE	35
#define ICMP_CODE_LEN		1

/* filter structure */
struct _filter_s {
	unsigned int offset; /* offset for the packet field */
	unsigned int len; /* length of the field */
	unsigned long long value; /* value of filter to match */
};

typedef union filter_s {
	struct _filter_s filter;
	char buff[16];
}filter_t;

/* queue structure for storing packets */

struct _user_buff {
	union _mac{
		struct ethhdr eth;
		unsigned char raw[14];
	}mac;
	union {
		struct iphdr iph;
		struct arphdr arph;
		unsigned char raw[20];
	}nh;
	union {
		struct tcphdr tcph;
		struct udphdr udph;
		struct icmphdr icmph;
		unsigned char raw[20];
	}th;
};

typedef union _pkt_hdrs {
	struct _user_buff pkt_hdr;
	unsigned char buff[56];
}user_buf;

