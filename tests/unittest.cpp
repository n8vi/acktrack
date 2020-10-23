#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
#include "../acktrack.h"

#define FINFLAG (1<<16)
#define SYNFLAG (1<<17)
#define RSTFLAG (1<<18)
#define PSHFLAG (1<<19)
#define ACKFLAG (1<<20)
#define URGFLAG (1<<21)

typedef struct ip4_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;   // Source address
    struct in_addr daddr;   // Destination address
    u_int   op_pad;         // Option + Padding
}ip4_header;

typedef struct ip6_header{
    u_int ver_class_flowlabel; // Version (4 bits) + traffic class (8 bits) + flow label (20 bits)
    u_short payload_len;        // Length of payload plus any extension headers
    u_char next_header;         // Type of next header
    u_char hop_limit;           // What it says on the tin
    struct in6_addr saddr;      // Source address
    struct in6_addr daddr;      // Destination address
}ip6_header;

typedef struct tcp_header{
    u_short sport;
    u_short dport;
    u_int seq_number;
    u_int ack_number;
    u_int offset_reserved_flags_window;
}tcp_header;

struct sockaddr *parseendpoint(const char* endpoint);
u_short get_port(const struct sockaddr *sa);
char *get_ip_str(const struct sockaddr *sa);
char *get_family(const struct sockaddr *sa);
char *get_filter(acktrack_t *acktrack);
u_int relseq(acktrack_t *acktrack, u_int absseq, int islseq);
int pcap_dloff(pcap_t *pd);
void CDECL acktrack_parsepacket(acktrack_t* acktrack, const struct pcap_pkthdr* pkthdr, const u_char* packet, sequence_event_t* event_data);


int init_suite1(void)
{
      return 0;
}

int clean_suite1(void)
{
      return 0;
}

void check_port(const char *s, int p)
{
	struct sockaddr *sa;
	unsigned short port;

	sa = parseendpoint((char*)s);
	port = ntohs(get_port(sa));
	CU_ASSERT(port == p);
}

void check_ip_str(const char *s, const char *i)
{
	struct sockaddr *sa;
        char *ipstr;

        sa = parseendpoint((char*)s);
        ipstr = get_ip_str(sa);
        CU_ASSERT(!strcmp(ipstr, i));
}

void check_family(const char *s, const char *f)
{
	struct sockaddr *sa;
	char *fam;

	sa = parseendpoint((char*)s);
	fam = get_family(sa);
	CU_ASSERT(!strcmp(fam, f));
}

char *get_endpointstring(const char *ip, const char *port)
{
	static char ret[55];

	if(strchr(ip, ':') != NULL) 
		snprintf(ret, 54, "[%s]:%s", ip, port);
	else
		snprintf(ret, 54, "%s:%s", ip, port);
	return ret;

}

void check_get_filter(const char *lip, const char *lport, const char *rip, const char *rport)
{
	acktrack_t *a;
	char *f;
	char filter[321] = "";

	a = (acktrack_t*)malloc(sizeof(acktrack_t));
	memcpy((void*)&(a->local), (void*)parseendpoint(get_endpointstring(lip, lport)), sizeof(a->local));
	memcpy((void*)&(a->remote), (void*)parseendpoint(get_endpointstring(rip, rport)), sizeof(a->remote));
	f = get_filter(a);
	snprintf(filter, 320, "tcp and ((src host %s and src port %s and dst host %s and dst port %s) or (src host %s and src port %s and dst host %s and dst port %s))",
			        lip, lport, rip, rport,
				rip, rport, lip, lport);
	CU_ASSERT(!strcmp(f, filter));
	
}

void test_get_port(void)
{
	check_port("127.0.0.1:80", 80);
	check_port("0.0.0.0:0", 0);
	check_port("255.255.255.255:65535", 65535);
	check_port("[::1]:80", 80);
	check_port("[::]:0", 0);
	check_port("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", 65535);
}

void test_get_ip_str(void)
{
	check_ip_str("127.0.0.1:80", "127.0.0.1");
	check_ip_str("0.0.0.0:0", "0.0.0.0");
	check_ip_str("255.255.255.255:65535", "255.255.255.255");
	check_ip_str("[::1]:80", "::1");
	check_ip_str("[::]:0", "::");
	check_ip_str("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

void test_get_family(void)
{
	check_family("127.0.0.1:80", "ipv4");
	check_family("0.0.0.0:0", "ipv4");
	check_family("255.255.255.255:65535", "ipv4");
	check_family("[::1]:80", "ipv6");
	check_family("[::]:0", "ipv6");
	check_family("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", "ipv6");
}

void test_get_filter(void)
{
    check_get_filter("10.10.10.10", "12345", "200.200.200.200", "200");
    check_get_filter("2002::ffff", "12345", "2600::1234", "200");
}

void test_relseq_rseq(void)
{
	acktrack_t *a;

	a = (acktrack_t*)malloc(sizeof(acktrack_t));
	a->rseqorig = 1000;
	CU_ASSERT(relseq(a,1024,0) == 24);
}

void test_relseq_lseq(void)
{
	acktrack_t *a;

	a = (acktrack_t*)malloc(sizeof(acktrack_t));
	a->lseqorig = 1000;
	CU_ASSERT(relseq(a,1024,1) == 24);
}

void test_acktrack_t(void)
{
    acktrack_t *a;
    int b;
    

    a = (acktrack_t*)malloc(sizeof(acktrack_t));
    a->lastrseq=1000;
    a->lastlseq=2000;
    a->lastrack=3000;
    a->lastlack=4000;
    b = acktrack_lastrseq(a);
    CU_ASSERT(b == 1000);
    b = acktrack_lastlseq(a);
    CU_ASSERT(b == 2000);
    b = acktrack_lastrack(a);
    CU_ASSERT(b == 3000);
    b = acktrack_lastlack(a);
    CU_ASSERT(b == 4000);
    a->lastrseq=4000;
    a->lastlseq=3000;
    a->lastrack=2000;
    a->lastlack=1000;
    b = acktrack_lastrseq(a);
    CU_ASSERT(b == 4000);
    b = acktrack_lastlseq(a);
    CU_ASSERT(b == 3000);
    b = acktrack_lastrack(a);
    CU_ASSERT(b == 2000);
    b = acktrack_lastlack(a);
    CU_ASSERT(b == 1000);
}



void check_socket_filter(const char *endpoint)
{
	struct sockaddr *rsa;
	struct sockaddr_storage lsa_storage;
	struct sockaddr *lsa = (struct sockaddr *)&lsa_storage;
	char temp[179];
	char filter[321];
	char host[55];
	char port[6];
	int s, r;
	socklen_t len;
	acktrack_t *a;

	rsa = parseendpoint(endpoint);
	strcpy(host, get_ip_str(rsa));
	sprintf(port, "%d", htons(get_port(rsa)));
	s = socket(rsa->sa_family, SOCK_STREAM, 0);
	r = -1;
	switch(rsa->sa_family) {
		case AF_INET:
			r = connect(s, rsa, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			r = connect(s, rsa, sizeof(struct sockaddr_in6));
			break;
			}
	CU_ASSERT(r != -1);
	len = sizeof(lsa_storage);
	r = getsockname(s, lsa, &len);
	CU_ASSERT(r != -1);
	snprintf(temp, 178, "tcp and ((src host %s and src port %d and dst host %s and dst port %s)", get_ip_str(lsa), ntohs(get_port(lsa)), host, port);
	snprintf(filter, 320, "%.177s or (src host %s and src port %s and dst host %s and dst port %d))", temp, host, port, get_ip_str(lsa), ntohs(get_port(lsa)));

	a = acktrack_create(s);

	CU_ASSERT(!strcmp(get_filter(a), filter));
}


void test_socket_filter(void)
{
	check_socket_filter("8.8.8.8:53");
	check_socket_filter("[2001:4860:4860::8888]:53");
}

void test_logmsg(void)
{
	FILE *fp;
	char s[64];
	char *l;
	acktrack_writelog("hello world");
	acktrack_openlog("test_logmsg.log");
	acktrack_writelog("hello world");
	acktrack_closelog();

	fp = fopen("test_logmsg.log", "r");
	CU_ASSERT_FATAL(fp != NULL);

	fgets(s, 64, fp);
	l = strchr(s, ' ')+1;
	l = strchr(l, ' ')+1;
	CU_ASSERT(!strcmp(l, "log file opened\n"));

	fgets(s, 64, fp);
	l = strchr(s, ' ')+1;
	l = strchr(l, ' ')+1;
	CU_ASSERT(!strcmp(l, "APP: hello world\n"));
	
	fclose(fp);
	acktrack_writelog("hello world");
}

void test_isfinishing(void)
{
    acktrack_t *a;

    a = (acktrack_t*)malloc(sizeof(acktrack_t));

    a->gotlfin = 0;
    a->gotrfin = 0;
    a->gotrst = 0;

    CU_ASSERT(!acktrack_isfinishing(a));
    // local side closed
    a->gotlfin = 1;
    CU_ASSERT(acktrack_isfinishing(a));
    a->gotlfin = 0;
    CU_ASSERT(!acktrack_isfinishing(a));
    // remote side closed
    a->gotrfin = 1;
    CU_ASSERT(acktrack_isfinishing(a));
    a->gotrfin = 0;
    CU_ASSERT(!acktrack_isfinishing(a));
    // either side reset
    a->gotrst = 1;
    CU_ASSERT(acktrack_isfinishing(a));
}

void test_isfinished(void)
{
    acktrack_t *a;

    a = (acktrack_t*)malloc(sizeof(acktrack_t));

    a->gotlfin = 0;
    a->gotrfin = 0;
    a->gotrst = 0;
    a->lastlack = a->lfinseq = a->lastrack = a->rfinseq = 0;

    CU_ASSERT(!acktrack_isfinished(a));
    a->gotrst = 1;
    CU_ASSERT(acktrack_isfinished(a));
    a->gotrst = 0;
    CU_ASSERT(!acktrack_isfinished(a));
    a->gotlfin = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->gotlfin = 0;
    a->gotrfin = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->gotlfin = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->lastlack = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->lastlack = 0;
    a->lastrack = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->lastlack = 1;
    CU_ASSERT(acktrack_isfinished(a));
    a->lfinseq = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->lfinseq = 0;
    a->rfinseq = 1;
    CU_ASSERT(!acktrack_isfinished(a));
    a->lfinseq = 1;
    CU_ASSERT(!acktrack_isfinished(a));
}

pcap_t *openloop(void)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) {
            return pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);
            }
        }

    return NULL;
}

void test_dloff(void)
{
    acktrack_t *a;

    a = (acktrack_t*)malloc(sizeof(acktrack_t));
    a->curcap = (acktrack_cap_t*)malloc(sizeof(acktrack_cap_t));
    a->curcap->handle = openloop();
    CU_ASSERT_FATAL(a->curcap->handle != NULL);    
    // printf("\n\n%d\n\n", pcap_dloff(a->curcap->handle));
    CU_ASSERT(pcap_dloff(a->curcap->handle) == 4);    

}

void test_parsepacket(void)
{
    acktrack_t a;
    struct pcap_pkthdr h;
    u_char p[65590];
    sequence_event_t e;
    ip4_header *i;
    tcp_header *t;
    u_int ip_len;
    u_int tcp_len;

    // Set up acktrack object
    a.curcap = (acktrack_cap_t*)malloc(sizeof(acktrack_cap_t));
    a.curcap->handle = openloop();
    CU_ASSERT_FATAL(a.curcap->handle != NULL);
    memcpy((void*)&(a.remote), (void*)parseendpoint("2.2.2.2:2"), sizeof(a.remote));
    memcpy((void*)&(a.local), (void*)parseendpoint("1.1.1.1:1"), sizeof(a.local));
    a.gotorigpkt = 0;
    
    // set up pkthdr object
    h.ts.tv_sec = 0;
    h.ts.tv_usec = 0;

    // set up packet data
    i = (ip4_header*)(p+pcap_dloff(a.curcap->handle));
    i->ver_ihl = 0x45;
    memcpy((void*)&(i->saddr), (void *)&(((struct sockaddr_in*)(&a.remote))->sin_addr), sizeof(struct sockaddr_in));
    memcpy((void*)&(i->daddr), (void *)&(((struct sockaddr_in*)(&a.local))->sin_addr), sizeof(struct sockaddr_in));
    ip_len = (i->ver_ihl & 0xf) * 4;
    t = (tcp_header*)((u_char*)i + ip_len);
    t->sport = ((struct sockaddr_in *)&(a.local))->sin_port;
    t->dport = ((struct sockaddr_in *)&(a.remote))->sin_port;
    t->offset_reserved_flags_window = htonl(ACKFLAG);
    t->seq_number = ntohl(1001);
    t->ack_number = ntohl(2001);

    tcp_len = 5; // for now
    t->offset_reserved_flags_window |= htonl((tcp_len/4)<<28);

    i->tlen = ip_len+(tcp_len*4);

    acktrack_parsepacket(&a, &h, p, &e);

    CU_ASSERT(a.lseqorig == 1000)
    CU_ASSERT(a.rseqorig == 2000)
    CU_ASSERT(a.gotorigpkt == 1);
    // CU_ASSERT(a.origtime == a.lastacktime);
    // CU_ASSERT(a.origtime != 0);
    CU_ASSERT(a.gotrfin == 0);
    CU_ASSERT(a.gotlfin == 0);
    CU_ASSERT(a.gotrst == 0);
    CU_ASSERT(a.lastlack == 2001);
    CU_ASSERT(a.lastrack == 0);
    CU_ASSERT(a.lastrseq == 1001);
    CU_ASSERT(a.lastlseq == 0);
    CU_ASSERT(a.lfinseq ==0);
    CU_ASSERT(a.rfinseq == 0);
    CU_ASSERT(a.lastpktislocal == 0);

    CU_ASSERT(e.is_local == 0);
    CU_ASSERT(e.seqno == 1001);
    CU_ASSERT(e.is_interesting == 1);
    CU_ASSERT(e.is_error == 0);
    CU_ASSERT(e.has_urg == 0);
    CU_ASSERT(e.has_ack == 1);
    CU_ASSERT(e.has_psh == 0);
    CU_ASSERT(e.has_rst == 0);
    CU_ASSERT(e.has_syn == 0);
    CU_ASSERT(e.has_fin == 0);
    
}

int main(void)
{
  CU_pSuite pSuite = NULL;

  if (CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite("Suite_1", init_suite1, clean_suite1);
   if (NULL == pSuite) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if (
       (NULL == CU_add_test(pSuite, "get_port()", test_get_port)) ||
       (NULL == CU_add_test(pSuite, "get_ip_str()", test_get_ip_str)) ||
       (NULL == CU_add_test(pSuite, "get_family()", test_get_family)) ||
       (NULL == CU_add_test(pSuite, "get_filter()", test_get_filter)) ||
       (NULL == CU_add_test(pSuite, "remote relseq()", test_relseq_rseq)) ||
       (NULL == CU_add_test(pSuite, "local relseq()", test_relseq_lseq)) ||
       (NULL == CU_add_test(pSuite, "lseq, rseq, lack, and rack", test_acktrack_t))||
       (NULL == CU_add_test(pSuite, "filter generated from socket", test_socket_filter)) ||
       (NULL == CU_add_test(pSuite, "isfinishing()", test_isfinishing)) ||
       (NULL == CU_add_test(pSuite, "isfinished()", test_isfinished)) ||
       (NULL == CU_add_test(pSuite, "logmsg()", test_logmsg)) ||
       (NULL == CU_add_test(pSuite, "pcap_parsepacket()", test_parsepacket))
      )
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* Run all tests using the CUnit Basic interface */
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   CU_cleanup_registry();
   return CU_get_error();
}

