

/* What I've learned here: TCP FIN packets can carry data, but nothing is transmitted from a given side after the FIN.
* Also the SYN and FIN flags, according to RFC793, consume 1 sequence number, as if they were a byte in the data stream.
* The end of the session can be detected by looking for a FIN from each end, and an ACK for both FINs.  We need to
* do this statefully since ACKs are what we care about.  SYN packets can also contain data in the case of Transactional
* TCP (T/TCP, see RFC1644) or TCP Fast Open (TFO, see RFC7413).
*
* THIS CODE ASSUMES SYN AND ACK NUMBERS ARE 1 AT THE END OF A THREE-WAY HANDSHAKE
* THIS ASSUMPTION IS INVALID IN THE CASE OF TFO OR T/TCP.
*/


#ifdef WIN32
// #include "pch.h"
#include <utility>
#include <limits.h>
#endif WIN32
#include "acktrack.h"

#define logmsg(fmt, ...) if (lfp) fprintf(lfp, fmt, ##__VA_ARGS__)
// #define logmsg(...) if (fp) fprintf(fp, __VA_ARGS__)

static FILE* lfp = 0;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;      // Source address
    struct in_addr daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct tcp_header{
    u_short sport;
    u_short dport;
    u_int seq_number;
    u_int ack_number;
    u_int offset_reserved_flags_window;
}tcp_header;

#define FINFLAG (1<<16)
#define SYNFLAG (1<<17)
#define RSTFLAG (1<<18)
#define PSHFLAG (1<<19)
#define ACKFLAG (1<<20)
#define URGFLAG (1<<21)

char* _cdecl acktrack_flagstr(u_int flags)
{
    static char ret[7] = "------";

    // ret[6] = '\0';


    if (flags & FINFLAG) {
        ret[5] = 'F';
    }
    else {
        ret[5] = '-';
    }
    if (flags & SYNFLAG) {
        ret[4] = 'S';
    }
    else {
        ret[4] = '-';
    }
    if (flags & RSTFLAG) {
        ret[3] = 'R';
    }
    else {
        ret[3] = '-';
    }
    if (flags & PSHFLAG) {
        ret[2] = 'P';
    }
    else {
        ret[2] = '-';
    }
    if (flags & ACKFLAG) {
        ret[1] = 'A';
    }
    else {
        ret[1] = '-';
    }
    if (flags & URGFLAG) {
        ret[0] = 'U';
    }
    else {
        ret[0] = '-';
    }
    return ret;
}

void _cdecl acktrack_free(acktrack_t* acktrack)
{
    if (acktrack) {
        if (lfp)
            logmsg("Closing ACKTRACK\n");
        if (acktrack->caps)
            free(acktrack->caps);
        free(acktrack);
    }
}

u_int relseq(acktrack_t *acktrack, u_int absseq, int islseq)
{
    if (islseq) {
        absseq -= acktrack->lseqorig;
    } else {
        absseq -= acktrack->rseqorig;
        }
    return absseq;
}

int _cdecl acktrack_openlog(char* logfile)
{
    lfp = fopen(logfile, "w");
    if (lfp == NULL)
        return 0;
    else
        logmsg("log file opened\n");
        return 1;
}

void _cdecl acktrack_writelog(char* msg)
{
    logmsg("APP: %s\n", msg);
}

void _cdecl acktrack_closelog(void)
{
    if (lfp)
        fclose(lfp);
}

int _cdecl acktrack_isfinished(acktrack_t *acktrack)
{
    if (!acktrack)
        return NULL;
    int ret = (acktrack->gotlfin && acktrack->gotrfin && acktrack->lastlack > acktrack->lfinseq&& acktrack->lastrack > acktrack->rfinseq) || acktrack->gotrst;
    logmsg("acktrack_isfinished: %d%d%d%d%d = %d\n", acktrack->gotlfin, acktrack->gotrfin, acktrack->lastlack > acktrack->lfinseq, acktrack->lastrack > acktrack->rfinseq, acktrack->gotrst, ret);
    return ret;
}

void _cdecl acktrack_parsepacket(acktrack_t* acktrack, const struct pcap_pkthdr* pkthdr, const u_char* packet, sequence_event_t* event_data)
{    
    ip_header* ih;
    tcp_header* th;
    u_int ip_len;
    u_int orfw;
    u_short sport;
    u_short dport;
    u_int absseqno;
    u_int absackno;
    u_int relseqno;
    u_int relackno;
    u_short datalen = 0;
    u_int tcp_len = 0;
    int islpkt = 0;
    int gotlack = 0;
    int gotlseq = 0;
    u_char *magic;

    bzero(event_data, sizeof(sequence_event_t));

    magic = (u_char*)(packet + 4);

    if (((*magic) & 0xf0) != 0x40)
        magic = (u_char*)(packet + 14);

    //ih = (ip_header*)(packet + 14);
    ih = (ip_header*)(magic);
    ip_len = (ih->ver_ihl & 0xf) * 4;
    th = (tcp_header*)((u_char*)ih + ip_len);

    orfw = htonl(th->offset_reserved_flags_window);

    sport = htons(th->sport);
    dport = htons(th->dport);

    absseqno = htonl(th->seq_number);
    absackno = htonl(th->ack_number);

    tcp_len = ((orfw & 0xf0000000) >> 28) * 4;
    datalen = ntohs(ih->tlen) - tcp_len - ip_len;

    if (orfw & SYNFLAG)
        datalen++;
    if (orfw & FINFLAG)
        datalen++;

    logmsg("acktrack_parsepacket(): %s:%d -> ", inet_ntoa(ih->saddr), ntohs(th->sport));
    logmsg("%s:%d.\n", inet_ntoa(ih->daddr), ntohs(th->dport));

    if (!acktrack->gotorigpkt) {
        logmsg("   --> Original packet.  Source deemed local.\n");
        memcpy(&acktrack->laddr, &ih->saddr, sizeof(struct in_addr));
        memcpy(&acktrack->raddr, &ih->daddr, sizeof(struct in_addr));
        acktrack->lport = htons(th->sport);
        acktrack->rport = htons(th->dport);
        acktrack->lseqorig = absseqno - 1;
        acktrack->rseqorig = absackno - 1;
        memcpy(&acktrack->origtime, &pkthdr->ts, sizeof(struct timeval));
        acktrack->gotorigpkt = 1;
        islpkt = 1;
    }
    else  if (!memcmp(&acktrack->laddr, &ih->saddr, sizeof(struct in_addr)) && sport == acktrack->lport) {
        islpkt = 1;
    }
    
    acktrack->lastpktislocal = islpkt;


    relseqno = relseq(acktrack, absseqno, islpkt);
    relackno = relseq(acktrack, absackno, !islpkt);

    if (islpkt) {
        if (absseqno > acktrack->lastlseq) {
            acktrack->lastlseq = absseqno;
            gotlseq = 1;
        }
        if (absackno > acktrack->lastrack) {
            acktrack->lastrack = absackno;
        }
    }
    else {
        if (absseqno > acktrack->lastrseq) {
            acktrack->lastrseq = absseqno;
        }
        if (absackno > acktrack->lastlack) {
            acktrack->lastlack = absackno;
            memcpy(&acktrack->lastacktime, &pkthdr->ts, sizeof(struct timeval));
            gotlack = 1;
        }
    }

    if (orfw & FINFLAG) {
        if (islpkt) {
            acktrack->gotlfin = 1;
            acktrack->lfinseq = absseqno;
        }
        else {
            acktrack->gotrfin = 1;
            acktrack->rfinseq = absseqno;
        }
    }

    if (orfw & RSTFLAG) {
        acktrack->gotrst = 1; /* needs further verification per rfc793 */
    }

    if (gotlack) {
        memcpy(&event_data->ts, &pkthdr->ts, sizeof(struct timeval));
        event_data->is_local = 0;
        event_data->seqno = relackno;
        event_data->is_interesting = 1;
    }
    else if (islpkt && datalen > 0) {
        memcpy(&event_data->ts, &pkthdr->ts, sizeof(struct timeval));
        event_data->is_local = 1;
        event_data->seqno = relseqno + datalen;
        event_data->is_interesting = 1;
    }
    logmsg("   --> is_local=%d seqno=%d is_interesting=%d, len=%d\n", event_data->is_local, event_data->seqno, event_data->is_interesting, datalen);

}

void _cdecl acktrack_callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    sequence_event_t event_data;
    acktrack_t* acktrack = (acktrack_t*)user;
    acktrack_cb_t cb = (acktrack_cb_t)acktrack->cb;

    acktrack_parsepacket(acktrack, pkthdr, packet, &event_data);

    if (event_data.is_interesting)
        cb(acktrack, &event_data);
}

void _cdecl acktrack_freeip4devs(pcap_if_t* f)
{
    pcap_if_t* n;

    while (f) {
        n = f->next;
        free(f);
        f = n;
    }
}

sequence_event_t *acktrack_next(acktrack_t *acktrack)
{

    // pcap_next_ex(pcap_t * p, struct pcap_pkthdr** pkt_header, const u_char * *pkt_data);
    // pcap_next_ex() returns 1 if the packet was read without problems, 
    // 0 if packets are being read from a live capture and the packet buffer timeout expired
    // PCAP_ERROR if an error occurred while reading the packet
    // and PCAP_ERROR_BREAK if packets are being read from a ``savefile''and there are no more packets to read from the savefile.
    // If PCAP_ERROR is returned, pcap_geterr(3PCAP) or pcap_perror(3PCAP) may be called with p as an argument to fetch or display the error text.

    // static pcap_t **descr = NULL; /* TODO: Move to acktrack_t structure.  This breaks the ability to do multiple simultaneous captures.  */
    struct pcap_pkthdr *pkthdr;
    pcap_t *orig;
    const u_char* packet;
    static sequence_event_t ret;
    int result;


    if (acktrack == NULL) {
        logmsg("ACKTRACK_NEXT CALLED ON NULL ACKTRACK\n");
        return NULL;
    }

    if (acktrack->curcap == NULL || *acktrack->curcap == NULL)
        acktrack->curcap = acktrack->caps;
  

    orig = *acktrack->curcap;

    // Since we're not relying on an "any" interface, we go once around the 
    // circle of interfaces and stop if we find something interesting

    do {
        result = pcap_next_ex(*acktrack->curcap, &pkthdr, &packet);
        switch (result) {
        case 0: // timeout expired
            logmsg("ACKTRACK_NEXT: timeout expired\n");
            ret.is_interesting = 0;
            break;
        case 1: // Got a packet
            logmsg("ACKTRACK_NEXT: GOT A PACKET\n");
            acktrack_parsepacket(acktrack, pkthdr, packet, &ret);
            break;
        case PCAP_ERROR: // got an error
            logmsg("ACKTRACK_NEXT: GOT AN ERROR\n");
            ret.is_error = 1;
            ret.is_interesting = 0;
            break;
        }
        acktrack->curcap++;
        if (*acktrack->curcap == NULL)
            acktrack->curcap = acktrack->caps;
    } while (*acktrack->curcap != orig && !ret.is_interesting);

    return &ret;
}

void _cdecl acktrack_dispatch(acktrack_t* acktrack, acktrack_cb_t cb)
{
    pcap_t** descr;

    acktrack->cb = cb;

    descr = acktrack->caps;

    while (*descr) {
        pcap_dispatch(*descr, -1, acktrack_callback, (u_char*)acktrack);
        descr++;
    }
}

acktrack_t *acktrack_openallinterfaces(char *filter)
// Why not check the routing table and pick the interface based on that you ask?  INBOUND packets are not
// bound to the rules of OUR routing table, they can come from literally anywhere.  Also, that sounds like
// a lot more work.

// Why not open "any" interface?  Because code may run on Windows, which doesn't have one.

//cleanup after this function does not require anything special because I did an array/pointer instead of a linked list
// You can just free() it
{
    pcap_addr_t *a;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_if_t *m = NULL;
    pcap_if_t *f = NULL;
    pcap_if_t *p = NULL;
    int i=0;
    int c=0;
    int has_ipv4_addr;
    pcap_t **descr;
    struct bpf_program fp;
    acktrack_t *ret;
    char errbuf[PCAP_ERRBUF_SIZE];

    logmsg("Filter: %s\n", filter);

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        has_ipv4_addr = 0;
        if (!strcmp(d->name, "\\Device\\NPF_Loopback"))
            has_ipv4_addr = 1;
        else for(a=d->addresses; a; a=a->next) {
            if (a->addr->sa_family == AF_INET)
                has_ipv4_addr = 1;
        }
        if (! has_ipv4_addr) {
            continue;
            }

        p = m;
        m = (pcap_if_t *)malloc(sizeof(pcap_if_t));
        memcpy(m,d,sizeof(pcap_if_t));
        m->next = NULL;
        if (p)
            p->next = m;
        if (!f)
            f = m;
        c++;

        }


    descr = (pcap_t**)malloc(sizeof(pcap_t *) * (c+1));
    i = 0;

    for (d=f; d!= NULL; d = d->next) {
        descr[i] = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);

        if(descr[i] == NULL) {
            logmsg("pcap_open_live failed for interface %s", d->name);
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
            }

    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
        if (pcap_compile(descr[i], &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            logmsg("pcap_compile failed");
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
        }

        // Load the compiled filter into the kernel
        if (pcap_setfilter(descr[i], &fp) == -1) {
            logmsg("pcap_setfilter failed");
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
        }

        pcap_set_timeout(descr[i], 1);
        // return value?

        i++;
        }


    descr[i] = NULL;

    pcap_freealldevs(alldevs);
    acktrack_freeip4devs(f);

    ret = (acktrack_t*)malloc(sizeof(acktrack_t));
    bzero(ret, sizeof(acktrack_t));
    ret->caps = descr;

    return(ret);

}


char* _cdecl acktrack_error(void)
{
#ifdef _WIN32
    char * buf;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
#else
    char* buf
    buf = strerror(errno);
#endif

    return (char*)buf;

}

acktrack_t* _cdecl acktrack_create_fromstrings(char* LocalEndPointStr, char* RemoteEndPointStr)
{
    char lepstr[22];
    char repstr[22];
    char *lipstr;
    char *ripstr;
    char* lportstr;
    char* rportstr;
    const char filter[201] = "";
    acktrack_t* ret;

    if (strlen(LocalEndPointStr) > 21 || strlen(RemoteEndPointStr) > 21) {
        return NULL;
    }

    strcpy(lepstr, LocalEndPointStr);
    strcpy(repstr, RemoteEndPointStr);

    lipstr = strtok(lepstr, ":");
    lportstr = strtok(NULL, ":");
    ripstr = strtok(repstr, ":");
    rportstr = strtok(NULL, ":");

    sprintf((char*)filter, "tcp and ((src host %s and src port %s and dst host %s and dst port %s) or (src host %s and src port %s and dst host %s and dst port %s))", 
        lipstr, lportstr, ripstr, rportstr,
        ripstr, rportstr, lipstr, lportstr);

    ret = acktrack_openallinterfaces((char*)filter);

    if (ret == NULL)
    {
        logmsg("acktrack_openallinterfaces failed");
        return ret;
    }

    return ret;
}

acktrack_t *acktrack_create(int sck) // no errbuf
{
    struct sockaddr_in laddr;
    struct sockaddr_in raddr;
    socklen_t len;
    int r;
    acktrack_t *ret;
    const char lsource[50] = "";
    const char ldest[50] = "";
    const char rsource[50] = "";
    const char rdest[50] = "";
    int type;
    int typelen = sizeof(type);
    const char filter[201] = "";

/**************************************************************************************[ maximum possible filter size ]****************************************************************************************\
                                                                                                       1         1         1         1         1         1         1         1         1         1         2
             1         2         3         4         5         6         7         8         9         0         1         2         3         4         5         6         7         8         9         0
    123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
    tcp and ((src host xxx.xxx.xxx.xxx and src port xxxxx and dst host xxx.xxx.xxx.xxx and dst port xxxxx) or (dst host xxx.xxx.xxx.xxx and dst port xxxxx and src host xxx.xxx.xxx.xxx and src port xxxxx))$
                                                                                                                                                                                                      _____/
                                                                                                                                                                                     (null terminator)
\**************************************************************************************************************************************************************************************************************/

    /*
    if (!fp) {
        printf("%s\n", strerror(errno));
        exit(0);
    }
    */


    logmsg("Log file opened\n");

    r = getsockopt(sck, SOL_SOCKET, SO_TYPE, (char*)&type, &typelen);

    if (r == -1) {

        
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected\n");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor\n");
        else
            logmsg("Determining socket type: %s\n", acktrack_error());
        
        return NULL;
    }

    if (type != SOCK_STREAM) {
        logmsg("Socket is not TCP");
        return NULL;
    }

    len = sizeof(raddr);

    r = getpeername(sck, (struct sockaddr*)&raddr, &len);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected\n");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor\n");
        else
            logmsg("Getting remote endpoint: %s\n", acktrack_error());

        return NULL;
        }

    if (raddr.sin_family != AF_INET) {
        logmsg("Socket is not ipv4\n");
        return NULL;
    }

    r = getsockname(sck, (struct sockaddr*)&laddr, &len);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected\n");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor\n");
        else
            logmsg("Getting local endpoint: %s\n", acktrack_error());

        return NULL;
        }


    // inet_ntoa returns a static buffer so we can't just do this all at once 
    sprintf((char*)rsource, "src host %s and src port %d", 
        (char*)inet_ntoa(raddr.sin_addr), 
        ntohs(raddr.sin_port)
        );

    sprintf((char*)ldest, "dst host %s and dst port %d", 
        (char*)inet_ntoa(laddr.sin_addr), 
        ntohs(laddr.sin_port)
        );

    sprintf((char*)lsource, "src host %s and src port %d", 
        (char*)inet_ntoa(laddr.sin_addr), 
        ntohs(laddr.sin_port)
        );

    sprintf((char*)rdest, "dst host %s and dst port %d", 
        (char*)inet_ntoa(raddr.sin_addr), 
        ntohs(raddr.sin_port)
        );

    sprintf((char *)filter, "tcp and ((%s and %s) or (%s and %s))", lsource, rdest, rsource, ldest);

    // printf("PCAP filter = %s\n", filter);

    ret = acktrack_openallinterfaces((char *)filter);

    if (ret == NULL)
    {
        logmsg("acktrack_openallinterfaces failed");
        return ret;
    }

    return ret;
}


/*
typedef struct sequence_event {
    struct timeval ts;
    u_char is_local;
    u_int seqno;
    u_char is_interesting;
    u_char is_error;
} sequence_event_t;
*/

long _cdecl acktrack_se_ts_sec(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_TS_SEC CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->ts.tv_sec;
}

long _cdecl acktrack_se_ts_usec(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_TS_USEC CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->ts.tv_usec;
}

u_int _cdecl acktrack_se_is_local(sequence_event_t *se)
{

    // printf("TX:is_interesting: %d\n", se->is_interesting);
    // printf("...: %d\n", acktrack_se_is_interesting(se));
    // printf("[%d]\n", se);

    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_LOCAL CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->is_local;
}

u_int _cdecl acktrack_se_seqno(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_SEQNO CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->seqno;
}

u_int _cdecl acktrack_se_is_interesting(sequence_event_t *se)
{
    /*
    if (se->is_interesting) {
        printf("IN");
    } else {
        printf("NI");
    }
    */
    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_INTERESTING CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->is_interesting;
}

u_int _cdecl acktrack_se_is_error(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_ERROR CALLED ON NULL SEQUENCE_EVENT\n");
        return NULL;
    }
    return se->is_error;
}