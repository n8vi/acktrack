

/* What I've learned here: TCP FIN packets can carry data, but nothing is transmitted from a given side after the FIN.
* Also the SYN and FIN flags, according to RFC793, consume 1 sequence number, as if they were a byte in the data stream.
* The end of the session can be detected by looking for a FIN from each end, and an ACK for both FINs.  We need to
* do this statefully since ACKs are what we care about.  SYN packets can also contain data in the case of Transactional
* TCP (T/TCP, see RFC1644) or TCP Fast Open (TFO, see RFC7413).
*
* THIS CODE ASSUMES SYN AND ACK NUMBERS ARE 1 AT THE END OF A THREE-WAY HANDSHAKE
* THIS ASSUMPTION IS INVALID IN THE CASE OF TFO OR T/TCP.
*/

#include "pcapsocket.h"

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

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

char* capsck_flagstr(u_int flags)
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

void capsck_free(capsck_t *capsck)
{
    free(capsck->caps);
    free(capsck);
}

u_int relseq(capsck_t *capsck, u_int absseq, int islseq)
{
    if (islseq) {
        absseq -= capsck->lseqorig;
    } else {
        absseq -= capsck->rseqorig;
        }
    return absseq;
}

int capsck_isfinished(capsck_t *capsck)
{
    // int ret = capsck->gotlfinack && capsck->gotrfinack;
    // return ret;

    // sleep(1);

    // printf(" {{ %d/%d %u > %u, %u > %u }}\n", capsck->gotlfin , capsck->gotrfin , relseq(capsck, capsck->lastlack, 1) , relseq(capsck, capsck->lfinseq, 1) , relseq(capsck, capsck->lastrack, 0) , relseq(capsck, capsck->rfinseq,0));

    return capsck->gotlfin && capsck->gotrfin && capsck->lastlack > capsck->lfinseq && capsck->lastrack > capsck->rfinseq;
}


void capsck_callback(u_char *user,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
  static int count = 1;
  capsck_t *scd = (capsck_t *)user;
  u_int ip_len;
  u_int absseqno;
  u_int absackno;
  u_int relseqno;
  u_int relackno;
  u_short sport;
  u_short dport;
  char s_src[16];
  char s_dst[16];
  int islpkt = 0;
  int gotlack = 0;
  int gotlseq = 0;
  u_short datalen = 0;
  u_short ihl = 0;
  u_int tcp_len = 0;
  u_int orfw;


  ip_header *ih;
  tcp_header *th;
  
  ih = (ip_header *) (packet + 14);
  ip_len = (ih->ver_ihl & 0xf) * 4;
  th = (tcp_header *) ((u_char*)ih + ip_len);

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

  if (!scd->gotorigpkt) {
    memcpy(&scd->laddr, &ih->saddr, sizeof(struct in_addr));
    memcpy(&scd->raddr, &ih->daddr, sizeof(struct in_addr));
    scd->lport = htons(th->sport);
    scd->rport = htons(th->dport);
    scd->lseqorig = absseqno - 1;
    scd->rseqorig = absackno - 1;
    memcpy(&scd->origtime, &pkthdr->ts, sizeof(struct timeval));
    scd->gotorigpkt = 1;
    islpkt = 1;
  } else  if (!memcmp(&scd->laddr, &ih->saddr, sizeof(struct in_addr)) && sport == scd->lport) {
    islpkt = 1;
  } else {
    // printf("remote packet %s:%d vs %s %d\n", inet_ntoa(scd->laddr), scd->lport, inet_ntoa(ih->saddr), sport);
    }

  scd->lastpktislocal = islpkt;


  relseqno = relseq(scd, absseqno, islpkt);
  relackno = relseq(scd, absackno, !islpkt);

/*
  if (islpkt && scd->gotrfin && absackno > scd->lastrseq) {
      printf("Got RFIN ACK: %d to %d\n", relackno, relseq(scd, scd->lastrseq, 0));
  }

  if (!islpkt && scd->gotlfin && absackno > scd->lastlseq) {
      printf("Got LFIN ACK: %d to %d\n", relackno, relseq(scd, scd->lastlseq, 1));
  }
*/

  if (islpkt) {
    // printf("local packet ack %lu - %lu  = %lu\n", scd->rseqorig, absackno, relackno);
    if (absseqno > scd->lastlseq) {
        scd->lastlseq = absseqno;
        // memcpy(&scd->lastseqtime, &pkthdr->ts, sizeof(struct timeval));
        gotlseq = 1;
        }
    if (absackno > scd->lastrack) {
        scd->lastrack = absackno;
        }
  } else {
    if (absseqno > scd->lastrseq) {
        scd->lastrseq = absseqno;
        }
    if (absackno > scd->lastlack) {
        scd->lastlack = absackno;
        memcpy(&scd->lastacktime, &pkthdr->ts, sizeof(struct timeval));
        gotlack = 1;
        }
    }

  if (orfw & FINFLAG) {
      if (islpkt) {
          scd->gotlfin = 1;
          scd->lfinseq = absseqno;
          // printf("Got LFIN: %d\n", relseqno);
      }
      else {
          scd->gotrfin = 1;
          scd->rfinseq = absseqno;
          // printf("Got RFIN: %d\n", relseqno);
      }
  }

  if (gotlack)
    printf("   ---> ACK: %lu.%.6lu: %8d\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, relackno);
  if (islpkt)
    printf("   <--- SEQ: %lu.%.6lu: %8d+%8d=%8d\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, relseqno, datalen, relseqno+datalen);


// ALL BELOW WILL BE USER CALLBACK SHORTLY

  /* blasted static buffers! */
  if (scd->lastpktislocal) {
      strcpy(s_src, inet_ntoa(scd->laddr));
      strcpy(s_dst, inet_ntoa(scd->raddr));
  } else {
      strcpy(s_src, inet_ntoa(scd->raddr));
      strcpy(s_dst, inet_ntoa(scd->laddr));
  }


  // printf("%lu.%.6lu: %15s:%.5d -> %15s:%.5d SEQ %.8d ACK %.8d [%s]\n", scd->lastpkttime.tv_sec, scd->lastpkttime.tv_usec, s_src, htons(th->sport), s_dst, htons(th->dport), relseqno, relackno, capsck_flagstr(scd->last_orfw));

  printf("%lu.%.6lu: %15s:%.5d -> %15s:%.5d LEN %.5d SEQ %.8d ACK %.8d [%s]\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, s_src, htons(th->sport), s_dst, htons(th->dport), pkthdr->len, relseqno, relackno, capsck_flagstr(orfw));

}

void capsck_freeip4devs(pcap_if_t* f)
{
    pcap_if_t *n;

    while (f) {
        n = f->next;
        free(f);
        f = n;
    }
}

capsck_t *capsck_openallinterfaces(char *filter, char* errbuf)
//TODO: clean up memory allocations in this function
//cleanup after this function does not require anything special because I did an array/pointer instead of a linked list
// You can just free() it
{
    pcap_addr_t *a;
    pcap_if_t *alldevs;
    // pcap_if_t *ipv4devs;
    pcap_if_t *d;
    pcap_if_t *m = NULL;
    pcap_if_t *f = NULL;
    pcap_if_t *p = NULL;
    int i=0;
    int c=0;
    int has_ipv4_addr;
    pcap_t **descr;
    struct bpf_program fp;
    capsck_t *ret;


    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        has_ipv4_addr = 0;
        for(a=d->addresses; a; a=a->next) {
            if (a->addr->sa_family == AF_INET)
                has_ipv4_addr = 1;
            }
        if (! has_ipv4_addr) {
            continue;
            }

        printf("  Interface %s has ipv4.  Adding to list of interfaces to capture on.\n", d->name);

        p = m;
        m = malloc(sizeof(pcap_if_t));
        memcpy(m,d,sizeof(pcap_if_t));
        m->next = NULL;
        if (p)
            p->next = m;
        if (!f)
            f = m;
        c++;

        }


    descr = malloc(sizeof(pcap_t *) * (c+1));
    i = 0;

    for (d=f; d!= NULL; d = d->next) {
        descr[i] = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);

        if(descr[i] == NULL) {
            sprintf(errbuf, "pcap_open_live failed for interface %s", d->name);
            capsck_freeip4devs(f);
            free(descr);
            return NULL;
            }

    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
        if (pcap_compile(descr[i], &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            strcpy(errbuf, "pcap_compile failed");
            capsck_freeip4devs(f);
            free(descr);
            return NULL;
        }

        // Load the compiled filter into the kernel
        if (pcap_setfilter(descr[i], &fp) == -1) {
            strcpy(errbuf, "pcap_setfilter failed");
            capsck_freeip4devs(f);
            free(descr);
            return NULL;
        }

        i++;
        }


    descr[i] = NULL;

    pcap_freealldevs(alldevs);
    capsck_freeip4devs(f);

    ret = malloc(sizeof(capsck_t));
    bzero(ret, sizeof(capsck_t));
    ret->caps = descr;

    return(ret);

}
    
capsck_t *capsck_create(int sck, char* errbuf)
{
    struct sockaddr_in laddr;
    struct sockaddr_in raddr;
    socklen_t len;
    int r;
    capsck_t *ret;
    const char lsource[50];
    const char ldest[50];
    const char rsource[50];
    const char rdest[50];
    int type;
    int typelen = sizeof(type);
    const char filter[201];

/**************************************************************************************[ maximum possible filter size ]****************************************************************************************\
                                                                                                       1         1         1         1         1         1         1         1         1         1         2
             1         2         3         4         5         6         7         8         9         0         1         2         3         4         5         6         7         8         9         0
    123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
    tcp and ((src host xxx.xxx.xxx.xxx and src port xxxxx and dst host xxx.xxx.xxx.xxx and dst port xxxxx) or (dst host xxx.xxx.xxx.xxx and dst port xxxxx and src host xxx.xxx.xxx.xxx and src port xxxxx))$
                                                                                                                                                                                                      _____/
                                                                                                                                                                                     (null terminator)
\**************************************************************************************************************************************************************************************************************/


    r = getsockopt(sck, SOL_SOCKET, SO_TYPE, (void*)&type, &typelen);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            strcpy(errbuf, "Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            strcpy(errbuf, "Bad socket descriptor");
        else
            strcpy(errbuf, "Unknown error getting socket type");

        return NULL;
    }

    if (type != SOCK_STREAM) {
        strcpy(errbuf, "Socket is not TCP");
        return NULL;
    }

    len = sizeof(raddr);

    r = getpeername(sck, (struct sockaddr*)&raddr, &len);

    if (r == -1) {
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            strcpy(errbuf, "Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            strcpy(errbuf, "Bad socket descriptor");
        else
            strcpy(errbuf, "Unknown error getting remote endpoint");

        return NULL;
        }

    if (raddr.sin_family != AF_INET) {
        strcpy(errbuf, "Socket is not ipv4");
        return NULL;
    }

    r = getsockname(sck, (struct sockaddr*)&laddr, &len);

    if (r == -1) {
        // the first two errors here should have been caught above on the remote end, but just in case ...
        if (errno == ENOTCONN)
            // Gotta connect before trying this, or we don't have two endpoints to bind to
            strcpy(errbuf, "Socket isn't connected");
        else if (errno == EBADF)
            // this integer not returned from socket(), or close() has been called on it
            strcpy(errbuf, "Bad socket descriptor");
        else
            strcpy(errbuf, "Unknown error getting local endpoint");

        return NULL;
        }

    // to make this work on windows it may be necessary to get an interface list with pcap_findalldevs_ex()
    // and pcap_open_live all interfaces, unless "any" is present (at which point we know it's linux)
    // Why not check the routing table and pick the interface based on that you ask?  INBOUND packets are not
    // bound to the rules of OUR routing table, they can come from literally anywhere.  Also, that sounds like
    // a lot more work.

    /*
    descr[0] = pcap_open_live("any", BUFSIZ, 0, -1,errbuf);
    descr[1] = NULL;
    */


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

    printf("PCAP filter = %s\n", filter);

    ret = capsck_openallinterfaces((char *)filter, errbuf);

    if (ret == NULL)
    {
        // strcpy(errbuf, "capsck_openallinterfaces failed");
        return ret;
    }


    return ret;
}

void capsck_dispatch(capsck_t *capsck)
{
    pcap_t **descr;
    // to make this work on windows it may be necessary to pcap_dispatch() the entire list of interfaces.
    // See comments above next to pcap_open_live()

    descr = capsck->caps;

    // printf("dispatch %p\n", descr);

    while(*descr) {
        pcap_dispatch(*descr, -1, capsck_callback, (u_char *)capsck);
        descr++;
        }
}
