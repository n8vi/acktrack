

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

typedef struct capsck_t{
    struct in_addr laddr;       /* local IP address  */
    struct in_addr raddr;       /* remote IP address */
    u_short lport;              /* local TCP port    */
    u_short rport;              /* remote TCP port   */
    int lseqorig;               /* Local initial sequence number SEE ABOVE */
    int rseqorig;               /* remote initial sequence number SEE ABOVE */
    u_int gotorigpkt;           /* nonzero if we have captured more than zero packets */
    struct timeval origtime;    /* time the original packet arrived */
    struct timeval lastpkttime; /* time the last packet arrived */
    int gotrfin;                /* nonzero if we've received a FIN from the remote */
    int gotlfin;                /* nonzero if we've sent a FIN */
    int lastrseq;               /* the last sequence number from the remote */
    int lastlseq;               /* our last sequence number */
    int lastrack;               /* the last ack we sent to the remote */
    int lastlack;               /* the last ack we got */
    int lfinseq;                /* the sequence number of our local FIN packet if gotlfin */
    int rfinseq;                /* the sequence number of the FIN from the remote if gotrfin */
    pcap_t **caps;              /* an array of pcap handles of all nterfaces with ipv4 on them */
    int lastpktislocal;         /* nonzero if last packet seen was sent by us */
    int last_orfw;              /* the value of the fourth octet of the last TCP header seen */
}capsck_t;

void capsck_free(capsck_t *capsck);
int capsck_isfinished(capsck_t *capsck);
capsck_t *capsck_create(int sck, char* errbuf);
void capsck_dispatch(capsck_t *user);
