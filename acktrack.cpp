

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

// #define logmsg(fmt, ...) if (lfp) {fprintf(lfp, fmt, ##__VA_ARGS__); fflush(lfp);}
// #define logmsg(...) if (fp) fprintf(fp, __VA_ARGS__)

static FILE* lfp = 0;

// need to add struct ip6_header for ipv6
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

void CDECL acktrack_free(acktrack_t* acktrack)
{
    if (acktrack) {
        if (lfp)
            logmsg("Closing ACKTRACK");
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

int CDECL acktrack_openlog(const char* logfile)
{
    lfp = fopen(logfile, "w");
    if (lfp == NULL)
        return 0;
    else
        logmsg("log file opened");
        return 1;
}

void CDECL acktrack_writelog(char* msg)
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

void CDECL acktrack_parsepacket(acktrack_t* acktrack, const struct pcap_pkthdr* pkthdr, const u_char* packet, sequence_event_t* event_data)
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

    // TODO: The "magic" here deals with ethernet captures (ethernet header followed by ip header, etc)
    // vs loopback captures (no ethernet header).  This is a fairly terrible way to handle this
    // and probably should be rethought before doing ipv6.
    // I've marked all the things that need to change with "TODO" throughout the code.

    // https://www.tcpdump.org/pcap.html (search in page for "assumes ethernet headers"
    // https://www.tcpdump.org/linktypes.html

    // =================================================================================================

    // Additional magic may be required here to handle skipping past ipv6 headers into the transport
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


    // magic = (u_char *)(packet->curcap->headerlen);

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

    logmsg("acktrack_parsepacket(): %s:%d -> %s:%d", inet_ntoa(ih->saddr), ntohs(th->sport), inet_ntoa(ih->daddr), ntohs(th->dport));

    if (!acktrack->gotorigpkt) {
        logmsg("   --> Original packet.  Source deemed local.");
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
    logmsg("   --> is_local=%d seqno=%d is_interesting=%d, len=%d", event_data->is_local, event_data->seqno, event_data->is_interesting, datalen);

}

void CDECL acktrack_callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    sequence_event_t event_data;
    acktrack_t* acktrack = (acktrack_t*)user;  /* TODO: here we have a packet to parse and know its header length in acktrack->curcap->headerlen */

    acktrack_cb_t cb = (acktrack_cb_t)acktrack->cb;

    acktrack_parsepacket(acktrack, pkthdr, packet, &event_data); /* TODO: pass in headerlength,  */

    if (event_data.is_interesting)
        cb(acktrack, &event_data);
}

void CDECL acktrack_freeip4devs(pcap_if_t* f)
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

    if (acktrack->curcap == NULL || acktrack->curcap->handle == NULL)
        acktrack->curcap = acktrack->caps;
  

    orig = acktrack->curcap;

    // Since we're not relying on an "any" interface, we go once around the 
    // circle of interfaces and stop if we find something interesting

    do {
        logmsg("pcap_next_ex(.%x)", acktrack);
        logmsg("pcap_next_ex(..%x)", acktrack->curcap);
        logmsg("pcap_next_ex(...%x)", acktrack->curcap->handle);
        result = pcap_next_ex(acktrack->curcap->handle, &pkthdr, &packet);
        switch (result) {
        case 0: // timeout expired
            logmsg("ACKTRACK_NEXT: timeout expired");
            ret.is_interesting = 0;
            break;
        case 1: // Got a packet
            logmsg("ACKTRACK_NEXT: GOT A PACKET");
            acktrack_parsepacket(acktrack, pkthdr, packet, &ret); /* TODO: here we have a packet to parse and know its header length in acktrack->curcap->headerlen */
            break;
        case PCAP_ERROR: // got an error
            logmsg("ACKTRACK_NEXT: GOT AN ERROR");
            ret.is_error = 1;
            ret.is_interesting = 0;
            break;
        }
        acktrack->curcap++;
        if (acktrack->curcap->handle == NULL)
            acktrack->curcap = acktrack->caps;
    } while (acktrack->curcap != orig && !ret.is_interesting);

    return &ret;
}

void CDECL acktrack_dispatch(acktrack_t* acktrack, acktrack_cb_t cb)
{
    acktrack->cb = (void*) cb;

    acktrack->curcap = acktrack->caps;

    while (acktrack->curcap->handle) {
        pcap_dispatch(acktrack->curcap->handle, -1, acktrack_callback, (u_char*)acktrack); /* TODO: here we have a packet to parse and know its header length in acktrack->curcap->headerlen */
        acktrack->curcap++;
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
    int has_ipv4_addr;  // will need "has_ipv6_addr" or similar to add ipv6 functionality
    acktrack_cap_t *descr;
    struct bpf_program fp;
    acktrack_t *ret;
    char errbuf[PCAP_ERRBUF_SIZE];

    logmsg("Filter: %s", filter);

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        has_ipv4_addr = 0;
        // if (!strcmp(d->name, "\\Device\\NPF_Loopback"))
        if (d->flags & PCAP_IF_LOOPBACK) {
            logmsg("Found loopback %s", d->name);
            has_ipv4_addr = 1;
        } else for(a=d->addresses; a; a=a->next) {
            if (a->addr->sa_family == AF_INET) {
                logmsg("Found iface with IPv4 address %s\n", d->name);
                has_ipv4_addr = 1;
                }
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


    descr = (acktrack_cap_t*)malloc(sizeof(acktrack_cap_t) * (c+1));
    i = 0;

    for (d=f; d!= NULL; d = d->next) {
        descr[i].handle = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);

        if (d->flags & PCAP_IF_LOOPBACK) {
            descr[i].headerlen = 4;
            logmsg("%s is loopback, thus headerlen 4", d->name);
        } else {
            logmsg("%s is ethernet, thus headerlen 14", d->name);
            descr[i].headerlen = 14;
            }

        if(descr[i].handle == NULL) {
            logmsg("pcap_open_live failed for interface %s", d->name);
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
            }

    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
        if (pcap_compile(descr[i].handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            logmsg("pcap_compile failed");
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
            }

        // Load the compiled filter into the kernel
        if (pcap_setfilter(descr[i].handle, &fp) == -1) {
            logmsg("pcap_setfilter failed");
            acktrack_freeip4devs(f);
            free(descr);
            return NULL;
            }

        pcap_set_timeout(descr[i].handle, 1);
        // return value?

        i++;
        }


    descr[i].handle = NULL;

    pcap_freealldevs(alldevs);
    acktrack_freeip4devs(f);

    ret = (acktrack_t*)malloc(sizeof(acktrack_t));
    bzero(ret, sizeof(acktrack_t));
    ret->caps = descr;

    return(ret);

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

acktrack_t* CDECL acktrack_create_fromstrings(char* LocalEndPointStr, char* RemoteEndPointStr)
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
    socklen_t typelen = sizeof(type);
    const char filter[201] = ""; // Will need to enlarge filter size to accomodate ipv6

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


    logmsg("Log file opened");

/*
acktrack.cpp: In function ‘acktrack_t* acktrack_create(int)’:
acktrack.cpp:569:68: error: invalid conversion from ‘int*’ to ‘socklen_t* {aka unsigned int*}’ [-fpermissive]
     r = getsockopt(sck, SOL_SOCKET, SO_TYPE, (char*)&type, &typelen);
                                                                    ^
*/

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

    len = sizeof(raddr);

    r = getpeername(sck, (struct sockaddr*)&raddr, &len);

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

    if (raddr.sin_family != AF_INET) { // We will need to update this to add ipv6
        logmsg("Socket is not ipv4");
        return NULL;
    }

    r = getsockname(sck, (struct sockaddr*)&laddr, &len);

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


    // inet_ntoa returns a static buffer so we can't just do this all at once 
    sprintf((char*)rsource, "src host %s and src port %d", 
        (char*)inet_ntoa(raddr.sin_addr),  // inet_ntoa will not work for ipv6
        ntohs(raddr.sin_port)
        );

    sprintf((char*)ldest, "dst host %s and dst port %d", 
        (char*)inet_ntoa(laddr.sin_addr),  // inet_ntoa will not work for ipv6
        ntohs(laddr.sin_port)
        );

    sprintf((char*)lsource, "src host %s and src port %d", 
        (char*)inet_ntoa(laddr.sin_addr),  // inet_ntoa will not work for ipv6
        ntohs(laddr.sin_port)
        );

    sprintf((char*)rdest, "dst host %s and dst port %d", 
        (char*)inet_ntoa(raddr.sin_addr),  // inet_ntoa will not work for ipv6
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

    // printf("TX:is_interesting: %d\n", se->is_interesting);
    // printf("...: %d\n", acktrack_se_is_interesting(se));
    // printf("[%d]\n", se);

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
    /*
    if (se->is_interesting) {
        printf("IN");
    } else {
        printf("NI");
    }
    */
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
