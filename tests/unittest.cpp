#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
#include "../acktrack.h"

struct sockaddr *parseendpoint(const char* endpoint);
u_short get_port(const struct sockaddr *sa);
char *get_ip_str(const struct sockaddr *sa);
char *get_family(const struct sockaddr *sa);
char *get_filter(acktrack_t *acktrack);
u_int relseq(acktrack_t *acktrack, u_int absseq, int islseq);


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
		sprintf(ret, "[%s]:%s", ip, port);
	else
		sprintf(ret, "%s:%s", ip, port);
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
	sprintf(filter, "tcp and ((src host %s and src port %s and dst host %s and dst port %s) or (src host %s and src port %s and dst host %s and dst port %s))",
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

/*
def test_socket_filter():
    d = DebugSession('fixture')
    s = d.call_func('sck_conn("8.8.8.8:53")')
    assert s != '-1', 'failed to create socket (invalid test result)'
    a = d.call_func(f'acktrack_create({s})')
    assert a != '0x0', 'failed to create acktrack_t object'
    f = d.call_func(f"get_filter({a})")
    assert re.search(r'^"tcp and \(\(src host ([0-9.]+) and src port ([0-9]+) and dst host 8.8.8.8 and dst port 53\) or \(src host 8.8.8.8 and src port 53 and dst host \1 and dst port \2\)\)"$', f), 'failed to generate accurate filter string'

*/

	// 2001:4860:4860::8888

void test_socket_filter(void)
{
	struct sockaddr *rsa;
	struct sockaddr_storage lsa_storage;
	struct sockaddr *lsa = (struct sockaddr *)&lsa_storage;;
	char filter[321];
	int s, r;
	socklen_t len;
	acktrack_t *a;

	rsa = parseendpoint("8.8.8.8:53");
	s = socket(AF_INET, SOCK_STREAM, 0);
	connect(s, rsa, sizeof(struct sockaddr_in));
	len = sizeof(lsa_storage);
	r = getsockname(s, lsa, &len);
	CU_ASSERT(r != -1);

	sprintf(filter, "tcp and ((src host %s and src port %d and dst host 8.8.8.8 and dst port 53)", get_ip_str(lsa), ntohs(get_port(lsa)));
	sprintf(filter, "%s or (src host 8.8.8.8 and src port 53 and dst host %s and dst port %d))", filter, get_ip_str(lsa), ntohs(get_port(lsa)));

	a = acktrack_create(s);

	CU_ASSERT(!strcmp(get_filter(a), filter));
        
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
       (NULL == CU_add_test(pSuite, "test get_port()", test_get_port)) ||
       (NULL == CU_add_test(pSuite, "test get_ip_str()", test_get_ip_str)) ||
       (NULL == CU_add_test(pSuite, "test get_family()", test_get_family)) ||
       (NULL == CU_add_test(pSuite, "test get_filter()", test_get_filter)) ||
       (NULL == CU_add_test(pSuite, "test remote relseq()", test_relseq_rseq)) ||
       (NULL == CU_add_test(pSuite, "test local relseq()", test_relseq_lseq)) ||
       (NULL == CU_add_test(pSuite, "test lseq, rseq, lack, and rack", test_acktrack_t))||
       (NULL == CU_add_test(pSuite, "test filter generated from socket", test_socket_filter))
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

