

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
#endif // WIN32
#include "acktrack.h"
#include <time.h>
#include <stdarg.h>

static FILE* lfp = 0;

// need to add struct ip6_header for ipv6
/* IPv4 header */
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

#define FINFLAG (1<<16)
#define SYNFLAG (1<<17)
#define RSTFLAG (1<<18)
#define PSHFLAG (1<<19)
#define ACKFLAG (1<<20)
#define URGFLAG (1<<21)

void logmsg(const char *fmt, ...)
{
    char now[26];
    va_list args;

    time_t dt;

    if (lfp) {
        dt = time(NULL);
        strftime(now, 26, "%Y-%m-%d %H:%M:%S", localtime(&dt));
        va_start(args, fmt);
        fprintf(lfp, "%s: ", now);
        vfprintf(lfp, fmt, args);
        fprintf(lfp, "\n");
        fflush(lfp);
        va_end(args);
        }
}

u_short get_port(const struct sockaddr *sa)
{
    static char s[6];
        switch(sa->sa_family) {
        case AF_INET:
            return ((struct sockaddr_in *)sa)->sin_port;
            break;
        case AF_INET6:
            return ((struct sockaddr_in6 *)sa)->sin6_port;
            break;
        default:
            return 0;
    }
}

char *get_ip_str(const struct sockaddr *sa)
{
    static char s[41];
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, 40);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, 40);
            break;

        default:
            return NULL;
    }

    return s;
}

char *get_family(const struct sockaddr *sa)
{
    static char ipv4[] = "ipv4";
    static char ipv6[] = "ipv6";
    switch(sa->sa_family) {
        case AF_INET:
            return ipv4;
            break;
        case AF_INET6:
            return ipv6;
            break;
        default:
            return NULL;
        }
}

struct sockaddr *parseendpoint(const char* endpoint)
{
    static struct sockaddr_storage sas;
    struct sockaddr_in *sa4 = (struct sockaddr_in*)&sas;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)&sas;
    struct sockaddr *sa = (struct sockaddr*)&sas;
    char epstr[48];
    char *ipstr;
    char *portstr;
    int ret;

    if (strlen(endpoint) > 47)
        return 0;

    strcpy(epstr, endpoint);

    ipstr = strtok(epstr, "]");
    portstr = strtok(NULL, "]");

    if (!portstr) {
        sa4->sin_family = AF_INET;
        ipstr = strtok(epstr, ":");
        if (!inet_pton(AF_INET, ipstr, &(sa4->sin_addr))) {
            return 0;
            }
        portstr = strtok(NULL, ":");
        sa4->sin_port = htons(atoi(portstr));
    } else {
        sa6->sin6_family = AF_INET6;
        if (*ipstr == '[')
            (ipstr)++;
        else {
            return 0;
            }
        if (*portstr == ':')
            (portstr)++;
        else {
            return 0;
            }
        if (!inet_pton(AF_INET6, ipstr, &(sa6->sin6_addr))){
            return 0;
            }
        sa6->sin6_port = htons(atoi(portstr));
        }
    return sa;
}

void CDECL acktrack_cap_free(acktrack_cap_t* cap)
{
    if (cap->handle)
        pcap_close(cap->handle);
        if (cap->bpfp) {
            pcap_freecode(cap->bpfp);
	    free(cap->bpfp);
	   // fprintf(stderr, " ====> freed code %p\n", cap->bpfp);
            }
        if(cap->iface_name)
            free(cap->iface_name);
}


void CDECL acktrack_free(acktrack_t* acktrack)
{
    acktrack_cap_t *p;

    if (acktrack) {
        if (lfp)
            logmsg("Closing ACKTRACK");
        if (p = acktrack->caps) {
            while (p->handle) {
                acktrack_cap_free(p);
                p++;
                }
            free(acktrack->caps);
            }
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

int CDECL acktrack_openlog(const char* logfile)
{
    lfp = fopen(logfile, "w");
    if (lfp == NULL)
        return 0;
    else
        logmsg("log file opened");
        return 1;
}

void CDECL acktrack_writelog(const char* msg)
{
    logmsg("APP: %s", msg);
}

void CDECL acktrack_closelog(void)
{
    if (lfp)
        fclose(lfp);
    lfp = (FILE*)0;
}

unsigned int CDECL acktrack_lastrseq(acktrack_t *acktrack)
{
    if (!acktrack)
        return 0;
    return acktrack->lastrseq;
}

unsigned int CDECL acktrack_lastlseq(acktrack_t *acktrack)
{
    if (!acktrack)
        return 0;
    return acktrack->lastlseq;
}

unsigned int CDECL acktrack_lastrack(acktrack_t *acktrack)
{
    if (!acktrack)
        return 0;
    return acktrack->lastrack;
}

unsigned int CDECL acktrack_lastlack(acktrack_t *acktrack)
{
    if (!acktrack)
        return 0;
    return acktrack->lastlack;
}


int CDECL acktrack_isfinishing(acktrack_t *acktrack)
{
    if (!acktrack)
        return 1;
    int ret = (acktrack->gotlfin || acktrack->gotrfin || acktrack->gotrst);
    logmsg("acktrack_isfinishing: %d%d%d = %d", acktrack->gotlfin, acktrack->gotrfin, acktrack->gotrst, ret);
    return ret;
}

int CDECL acktrack_isfinished(acktrack_t *acktrack)
{
    if (!acktrack)
        return 1;
    int ret = (acktrack->gotlfin && acktrack->gotrfin && acktrack->lastlack > acktrack->lfinseq&& acktrack->lastrack > acktrack->rfinseq) || acktrack->gotrst;
    logmsg("acktrack_isfinished: %d%d%d%d%d = %d", acktrack->gotlfin, acktrack->gotrfin, acktrack->lastlack > acktrack->lfinseq, acktrack->lastrack > acktrack->rfinseq, acktrack->gotrst, ret);
    return ret;
}

// nearly 100% swiped from dsniff
int pcap_dloff(pcap_t *pd)
{
    int offset = -1;
            
    switch (pcap_datalink(pd)) {
        case DLT_RAW:     // Teredo, for one example.  
            offset = 0;      // No need for "ethertype" or hardware addresses
	    break;
        case DLT_EN10MB:  // 802.3 10bT, 802.3z 100bTX, 802.3ab 1000bT, etc
            offset = 14;     // 6 octet source and dest mac plus 2 octet ethertype
            break;
        case DLT_IEEE802: // 802.5 Token ring (with a silly constant name)
            offset = 22;     // Probably will never be used, but it was in dsniff, so why the hell not
            break;
        case DLT_FDDI:    // An even more dubious dsniff inheritance
            offset = 21; 
            break;
    #ifdef DLT_LOOP
        case DLT_LOOP:    // Quite likely what it says on the tin
    #endif
        case DLT_NULL:    // etc ...
            offset = 4;
            break;
        default:
            // warnx("unsupported datalink type");
            break;
        }
    return (offset);
}


void CDECL acktrack_parsepacket(acktrack_t* acktrack, const struct pcap_pkthdr* pkthdr, const u_char* packet, sequence_event_t* event_data)
{    
    ip4_header* ih4;
    ip6_header* ih6;
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
    u_char *buf;
    int skiplen = 14; // ethernet by default
    u_short plen;
    int i;

    struct sockaddr_in *sin;


    bzero(event_data, sizeof(sequence_event_t));

    // Magic may be required here to handle skipping past ipv6 headers into the transport
    // layer header.  IPv6 has no IHL field.  You may read that IPv6 packets have a fixed 40-octet
    // header. That's nice, right?  Well, that's true only if the packet has no iextension headers.
    // And you can only figure out options by looking at the "next header" field.

    // From RFC2460, the original IPv6 RFC, IPv6 extension headers are discussed as follows:

/*
   If, as a result of processing a header, a node is required to proceed
   to the next header but the Next Header value in the current header is
   unrecognized by the node, it should discard the packet and send an
   ICMP Parameter Problem message to the source of the packet, with an
   ICMP Code value of 1 ("unrecognized Next Header type encountered")
   and the ICMP Pointer field containing the offset of the unrecognized
   value within the original packet.  The same action should be taken if
   a node encounters a Next Header value of zero in any header other
   than an IPv6 header.
*/

    // This confirms my initial suspicion that IPv6 requires a stack implementation have perfect
    // knowledge of all possible IPv6 options, including ones defined in the future, in order to
    // operate correctly.  This is terrible, guys!
    // RFC6564 helps a bit by defining a uniform TLV format for future headers, but ones defined 
    // prior to this will not have this TLV format.  RFC7045 clears this up a bit but claims 

/* 
   The present document does not intend to solve this problem,
   which is caused by the fundamental architecture of IPv6 extension
   headers.  This document focuses on clarifying how the header chain
   should be handled in the current IPv6 architecture.
*/

    // Now, clearly IPv6 is parsable, since wireshark can do it, but it requires a bit of a dance.

    // IT SHOULD BE NOTED THAT RFC8200 OBSOLETES RFC2460 AND SUPERCEDES RFC7045 BY 3.5 YEARS
    // RFC8200 ALSO GAINED STD STATUS IN 2018 AS STD86
    // PERHAPS IT IS WORTH A COMPLETE READ

    skiplen = pcap_dloff(acktrack->curcap->handle);
    // skiplen = pcap_dloff(*(acktrack->curcap));

    logmsg("Skipping %d octet header", skiplen);

    buf = (u_char*)(packet + skiplen);

    /*
    printf("    GOTPKT: ");

    for (i=0; i<60; i++) {
        printf("%.2x ", ((unsigned char *)buf)[i]);
        }
    printf("\n");

    printf("  \\-=->");
    for (i=0; i<16; i++) {
        printf("%.2x ", ((unsigned char *)th)[i]);
        }
    printf("\n");

    fflush(stdout);
    */

    if (acktrack->remote.ss_family == AF_INET) {
        ih4 = (ip4_header*)(buf);
        ip_len = (ih4->ver_ihl & 0xf) * 4;
        th = (tcp_header*)((u_char*)ih4 + ip_len);
        plen = ntohs(ih4->tlen)-ip_len;
    } else if (acktrack->remote.ss_family == AF_INET6) {
        ih6 = (ip6_header*)(buf);
        // if (ntohs(ih6->next_header) != 6) {
        if (ih6->next_header != 6) {
            logmsg("ACKTRACK_NEXT: GOT NON-TCP packet");
            event_data->is_error = 1;
            event_data->is_interesting = 0;
            return;
            }
        th = (tcp_header*)((u_char*)ih6 + 40); /* FIXME THIS DOES NOT HANDLE EXTENSION HEADERS */
        plen = ntohs(ih6->payload_len);
    } else {
        logmsg(" unknown proto\n");
        }

    orfw = htonl(th->offset_reserved_flags_window);

    sport = htons(th->sport);
    dport = htons(th->dport);

    absseqno = htonl(th->seq_number);
    absackno = htonl(th->ack_number);

    tcp_len = ((orfw & 0xf0000000) >> 28) * 4;
    // datalen = ntohs(ih4->tlen) - tcp_len - ip_len;
    datalen = plen - tcp_len;

    if (orfw & FINFLAG) {
        datalen++;
        event_data->has_fin = 1;
    }
    if (orfw & SYNFLAG) {
        datalen++;
        event_data->has_syn = 1;
    }
    if (orfw & RSTFLAG) {
        event_data->has_rst = 1;
    }
    if (orfw & PSHFLAG) {
        event_data->has_psh = 1;
    }
    if (orfw & ACKFLAG) {
        event_data->has_ack = 1;
    }
    if (orfw & URGFLAG) {
        event_data->has_urg = 1;
    }

    // FIXME: explodes on IPv6
    // logmsg("acktrack_parsepacket(): %s:%d -> %s:%d", inet_ntoa(ih4->saddr), ntohs(th->sport), inet_ntoa(ih4->daddr), ntohs(th->dport));

    if (!acktrack->gotorigpkt) {
        /* TODO: perhaps assert following "should" */
        logmsg("   --> Original packet.  Source should be local.");
        
        acktrack->lseqorig = absseqno - 1;
        acktrack->rseqorig = absackno - 1;
        memcpy(&(acktrack->origtime), &pkthdr->ts, sizeof(struct timeval));
        acktrack->gotorigpkt = 1;
        // islpkt = 1;
    }
    if (acktrack->remote.ss_family == AF_INET) {
        if (!memcmp((void *)&(((struct sockaddr_in*)(&acktrack->local))->sin_addr), (void*)&(ih4->saddr), sizeof(struct in_addr)) && th->sport == ((struct sockaddr_in *)&(acktrack->local))->sin_port) {
            islpkt = 1;
        }
    }
    if (acktrack->remote.ss_family == AF_INET6) {
        if (!memcmp((void *)&(((struct sockaddr_in6*)(&acktrack->local))->sin6_addr), (void*)&(ih6->saddr), sizeof(struct in_addr)) && th->sport == ((struct sockaddr_in6 *)&(acktrack->local))->sin6_port) {
            islpkt = 1;
        }
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
    } else {
    }
    logmsg("   --> is_local=%d seqno=%d is_interesting=%d, len=%d", event_data->is_local, event_data->seqno, event_data->is_interesting, datalen);


}

void CDECL acktrack_callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    sequence_event_t event_data;
    acktrack_t* acktrack = (acktrack_t*)user; 

    acktrack_cb_t cb = (acktrack_cb_t)acktrack->cb;

    acktrack_parsepacket(acktrack, pkthdr, packet, &event_data);

    if (event_data.is_interesting)
        cb(acktrack, &event_data);
}

void CDECL acktrack_freedevs(pcap_if_t* f) 
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

    struct pcap_pkthdr *pkthdr;
    acktrack_cap_t *orig;
    const u_char* packet;
    static sequence_event_t ret;
    int result;


    if (acktrack == NULL) {
        logmsg("ACKTRACK_NEXT CALLED ON NULL ACKTRACK");
        return NULL;
    }

    if (acktrack->curcap == NULL || acktrack->curcap->handle == NULL) {
    // if (acktrack->curcap == NULL || *(acktrack->curcap) == NULL) {
        acktrack->curcap = acktrack->caps;
        }
  
/*
    if (acktrack->curcap == NULL || *(acktrack->curcap) == NULL) {
        logmsg("interface list got mangled?");
        return NULL;
        }
*/

    orig = acktrack->curcap;

    // Since we're not relying on an "any" interface, we go once around the 
    // circle of interfaces and stop if we find something interesting

    do {
        logmsg("pcap_next_ex(.%x)", acktrack);
        logmsg("pcap_next_ex(..%x)", acktrack->curcap);
        // logmsg("pcap_next_ex(...%x)", acktrack->curcap->handle);
        logmsg("pcap_next_ex(...%x)", acktrack->curcap);
        // result = pcap_next_ex(acktrack->curcap->handle, &pkthdr, &packet);
        result = pcap_next_ex(acktrack->curcap->handle, &pkthdr, &packet);
        switch (result) {
        case 0: // timeout expired
            logmsg("ACKTRACK_NEXT: timeout expired");
            ret.is_interesting = 0;
            break;
        case 1: // Got a packet
            logmsg("ACKTRACK_NEXT: GOT A PACKET");
            acktrack_parsepacket(acktrack, pkthdr, packet, &ret);
            break;
        case PCAP_ERROR: // got an error
            logmsg("ACKTRACK_NEXT: GOT AN ERROR");
            ret.is_error = 1;
            ret.is_interesting = 0;
            break;
        }
        acktrack->curcap++;
        if (acktrack->curcap->handle == NULL)
        // if (*(acktrack->curcap) == NULL)
            acktrack->curcap = acktrack->caps;
    } while (acktrack->curcap != orig && !ret.is_interesting);

    return &ret;
}

void CDECL acktrack_dispatch(acktrack_t* acktrack, acktrack_cb_t cb)
{
    acktrack->cb = (void*) cb;

    acktrack->curcap = acktrack->caps;

    while (acktrack->curcap->handle) {
    // while (*(acktrack->curcap)) {
        pcap_dispatch(acktrack->curcap->handle, -1, acktrack_callback, (u_char*)acktrack);
        // pcap_dispatch(*(acktrack->curcap), -1, acktrack_callback, (u_char*)acktrack);
        acktrack->curcap++;
    }
}

char* CDECL acktrack_error(void)
{
#ifdef _WIN32
    char * buf;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, NULL);
#else
    char* buf;
    buf = strerror(errno);
#endif

    return (char*)buf;

}

char *get_filter(acktrack_t *acktrack)
{
    static char filter[321] = "";
    char lipstr[46];
    char ripstr[46];
    u_short lport;
    u_short rport;

    strcpy(lipstr, get_ip_str((const struct sockaddr *)&(acktrack->local)));
    strcpy(ripstr, get_ip_str((const struct sockaddr *)&(acktrack->remote)));
    lport = get_port((const struct sockaddr *)&(acktrack->local));
    rport = get_port((const struct sockaddr *)&(acktrack->remote));

    sprintf((char*)filter, "tcp and ((src host %s and src port %d and dst host %s and dst port %d) or (src host %s and src port %d and dst host %s and dst port %d))",
        lipstr, ntohs(lport), ripstr, ntohs(rport),
        ripstr, ntohs(rport), lipstr, ntohs(lport));

    return filter;        
}

int acktrack_opencap(acktrack_t *acktrack)
// Why not check the routing table and pick the interface based on that you ask?  INBOUND packets are not
// bound to the rules of OUR routing table, they can come from literally anywhere.  Also, that sounds like
// a lot more work.

// Why not open "any" interface?  Because code may run on Windows, which doesn't have one.
{
    char *filter;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *d;
    pcap_addr_t *a;
    pcap_if_t *p = NULL;
    pcap_if_t *m = NULL;
    pcap_if_t *f = NULL;
    int c=0;
    acktrack_cap_t *descr;
    int has_addr;
    int i=0;
    struct bpf_program fp;

    filter = get_filter(acktrack);
        
    logmsg("filter: %s", filter);

    if (acktrack->remote.ss_family != AF_INET && acktrack->remote.ss_family != AF_INET6) { // We will need to update this to add ipv6
        logmsg("Socket is not ipv4 or ipv6");
        return 5;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return 1;

    for (d=alldevs; d != NULL; d = d->next) {
        has_addr = 0;
        if (d->flags & PCAP_IF_LOOPBACK) {
            logmsg("Found loopback %s", d->name);
            has_addr = 1;
        } else for(a=d->addresses; a; a=a->next) {
            if (acktrack->remote.ss_family == AF_INET && a->addr->sa_family == AF_INET) {
                logmsg("Found iface with IPv4 address %s", d->name);
                has_addr = 1;
                }
            if (acktrack->remote.ss_family == AF_INET6 && a->addr->sa_family == AF_INET6) {
                logmsg("Found iface with IPv6 address %s", d->name);
                has_addr = 1;
                }
        }
        if (! has_addr) {
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

    descr = (acktrack_cap_t*)malloc(sizeof(acktrack_cap_t) * (c+1));
    // descr = (pcap_t **)malloc(sizeof(pcap_t*)*(c+1));
    i = 0;

    for (d=f; d!= NULL; d = d->next) {

        descr[i].handle = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);
        // descr[i] = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);
	
        if(descr[i].handle == NULL) {
        // if(descr[i] == NULL) {
            logmsg("pcap_open_live failed for interface %s", d->name);
            acktrack_freedevs(f);
            free(descr);
            return 2;
            }

        descr[i].iface_name = (char*)malloc(strlen(d->name)+1);
        if (descr[i].iface_name)
            strcpy(descr[i].iface_name, d->name);


    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
        descr[i].bpfp = (struct bpf_program*)malloc(sizeof(bpf_program));
//	fprintf(stderr, "\n =====> allocated code %p\n", descr[i].bpfp);
        if (pcap_compile(descr[i].handle, descr[i].bpfp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        // // if (pcap_compile(descr[i].handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        // if (pcap_compile(descr[i], &(acktrack->bpfp), filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            logmsg("pcap_compile failed");
            acktrack_freedevs(f);
            free(descr);
            return 3;
            }

        // Load the compiled filter into the kernel
        // // if (pcap_setfilter(descr[i].handle, &fp) == -1) {
        if (pcap_setfilter(descr[i].handle, descr[i].bpfp) == -1) {
        // if (pcap_setfilter(descr[i], &(acktrack->bpfp)) == -1) {
            logmsg("pcap_setfilter failed");
            acktrack_freedevs(f);
            acktrack_cap_free(descr);
            free(descr);
            return 4;
            }

        pcap_set_timeout(descr[i].handle, 1);
        // pcap_set_timeout(descr[i], 1);

        i++;
        }


    descr[i].handle = NULL;
    //descr[i] = NULL;

    pcap_freealldevs(alldevs);
    acktrack_freedevs(f);

    acktrack->caps = descr;

    return 0;
}


acktrack_t* CDECL acktrack_create_fromstrings(const char* LocalEndPointStr, const char* RemoteEndPointStr)
{
    static acktrack_t *ret;

    ret = (acktrack_t*)malloc(sizeof(acktrack_t));

    bzero(ret, sizeof(acktrack_t));

    memcpy((void*)&(ret->local), (void*)parseendpoint(LocalEndPointStr), sizeof(ret->local));
    memcpy((void*)&(ret->remote), (void*)parseendpoint(RemoteEndPointStr), sizeof(ret->remote));

    acktrack_opencap(ret);

    return ret;
}

acktrack_t* CDECL acktrack_create(int sck)
{
    static acktrack_t *ret;
    int r;
    int type;
    socklen_t typelen = sizeof(type);
    socklen_t len;

    ret = (acktrack_t*)malloc(sizeof(acktrack_t));
    bzero(ret, sizeof(acktrack_t));

    r = getsockopt(sck, SOL_SOCKET, SO_TYPE, (char*)&type, &typelen);

    if (r == -1) {


        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor");
        else
            logmsg("Determining socket type: %s", acktrack_error());

        return NULL;
    }


    if (type != SOCK_STREAM) {
        logmsg("Socket is not TCP");
        return NULL;
    }

    len = sizeof(ret->remote);

    r = getpeername(sck, (struct sockaddr*)&(ret->remote), &len);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor");
        else
            logmsg("Getting remote endpoint: %s", acktrack_error());

        return NULL;
        }


    r = getsockname(sck, (struct sockaddr*)&(ret->local), &len);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            logmsg("Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            logmsg("Bad socket descriptor");
        else
            logmsg("Getting local endpoint: %s", acktrack_error());

        return NULL;
        }

    acktrack_opencap(ret);

    return ret;
}

long CDECL acktrack_se_ts_sec(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_TS_SEC CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->ts.tv_sec;
}

long CDECL acktrack_se_ts_usec(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_TS_USEC CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->ts.tv_usec;
}

u_int CDECL acktrack_se_is_local(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_LOCAL CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->is_local;
}

u_int CDECL acktrack_se_seqno(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_SEQNO CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->seqno;
}

u_int CDECL acktrack_se_is_interesting(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_INTERESTING CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->is_interesting;
}

u_int CDECL acktrack_se_is_error(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_IS_ERROR CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->is_error;
}

u_int CDECL acktrack_se_has_urg(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_URG CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_urg;
}

u_int CDECL acktrack_se_has_ack(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_ACK CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_ack;
}

u_int CDECL acktrack_se_has_psh(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_PSH CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_psh;
}

u_int CDECL acktrack_se_has_rst(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_RST CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_rst;
}

u_int CDECL acktrack_se_has_syn(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_SYN CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_syn;
}

u_int CDECL acktrack_se_has_fin(sequence_event_t *se)
{
    if (!se) {
        logmsg("SEQUENCE_EVENT_HAS_FIN CALLED ON NULL SEQUENCE_EVENT");
        return 0;
    }
    return se->has_fin;
}
