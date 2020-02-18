

/* What I've learned here: TCP FIN packets can carry data, but nothing is transmitted from a given side after the FIN.
* Also the SYN and FIN flags, according to RFC793, consume 1 sequence number, as if they were a byte in the data stream.
* The end of the session can be detected by looking for a FIN from each end, and an ACK for both FINs.  We need to
* do this statefully since ACKs are what we care about.  SYN packets can also contain data in the case of Transactional
* TCP (T/TCP, see RFC1644) or TCP Fast Open (TFO, see RFC7413).
*
* THIS CODE ASSUMES SYN AND ACK NUMBERS ARE 1 AT THE END OF A THREE-WAY HANDSHAKE
* THIS ASSUMPTION IS INVALID IN THE CASE OF TFO OR T/TCP.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include "pcap.h"

#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <sys/select.h>
#else
#include <windows.h>
#include <winsock.h>
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif

#ifndef PCAP_NETMASK_UNKNOWN 
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#ifdef WIN32
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#define sleep(x) Sleep((x*1000))
#endif


typedef struct sequence_event {
    struct timeval ts;
    u_char is_local;
    u_int seqno;
} sequence_event_t;

typedef struct capsck_t{
    struct in_addr laddr;        /* local IP address  */
    struct in_addr raddr;        /* remote IP address */
    u_short lport;               /* local TCP port    */
    u_short rport;               /* remote TCP port   */
    int lseqorig;                /* Local initial sequence number SEE ABOVE */
    int rseqorig;                /* remote initial sequence number SEE ABOVE */
    u_int gotorigpkt;            /* nonzero if we have captured more than zero packets */
    struct timeval origtime;     /* time the original packet arrived */
    struct timeval lastacktime;  /* time the last ACK arrived from the remote */
    struct timeval lastsenttime; /* time we sent the last SEQ to the remote */
    int gotrfin;                 /* nonzero if we've received a FIN from the remote */
    int gotlfin;                 /* nonzero if we've sent a FIN */
    int lastrseq;                /* the last sequence number from the remote */
    int lastlseq;                /* our last sequence number */
    int lastrack;                /* the last ack we sent to the remote */
    int lastlack;                /* the last ack we got */
    int lfinseq;                 /* the sequence number of our local FIN packet if gotlfin */
    int rfinseq;                 /* the sequence number of the FIN from the remote if gotrfin */
    pcap_t **caps;               /* an array of pcap handles of all nterfaces with ipv4 on them */
    int lastpktislocal;          /* nonzero if last packet seen was sent by us */
    void *cb;
}capsck_t;

typedef void (*capsck_cb_t)(capsck_t*, sequence_event_t *);

void capsck_free(capsck_t *capsck);
int capsck_isfinished(capsck_t *capsck);
capsck_t *capsck_create(int sck, char* errbuf, capsck_cb_t cb);
void capsck_dispatch(capsck_t *capsck);
