

/* What I've learned here: TCP FIN packets can carry data, but nothing is transmitted from a given side after the FIN.
* Also the SYN and FIN flags, according to RFC793, consume 1 sequence number, as if they were a byte in the data stream.
* The end of the session can be detected by looking for a FIN from each end, and an ACK for both FINs.  We need to
* do this statefully since ACKs are what we care about.  SYN packets can also contain data in the case of Transactional
* TCP (T/TCP, see RFC1644) or TCP Fast Open (TFO, see RFC7413).
*
* THIS CODE ASSUMES SYN AND ACK NUMBERS ARE 1 AT THE END OF A THREE-WAY HANDSHAKE
* THIS ASSUMPTION IS INVALID IN THE CASE OF TFO OR T/TCP.
*/

#pragma once

// #ifdef _WIN32
#ifdef PCAPSOCKET_EXPORTS
#define PCAPSOCKET_API __declspec(dllexport)
#else
#define PCAPSOCKET_API __declspec(dllimport)
#endif
// #endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include "pcap.h"

#ifndef _WIN32
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

#ifdef _WIN32
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#define sleep(x) Sleep((x*1000))
#endif


typedef struct sequence_event {
    struct timeval ts;
    u_char is_local;
    u_int seqno;
    u_char is_interesting;
    u_char is_error;
} sequence_event_t;

/* The following struct may be subject to change */
typedef struct acktrack_t{
    struct in_addr laddr;        /* local IP address  */
    struct in_addr raddr;        /* remote IP address */
    u_short lport;               /* local TCP port    */
    u_short rport;               /* remote TCP port   */
    u_int lseqorig;                /* Local initial sequence number SEE ABOVE */
    u_int rseqorig;                /* remote initial sequence number SEE ABOVE */
    u_int gotorigpkt;            /* nonzero if we have captured more than zero packets */
    struct timeval origtime;     /* time the original packet arrived */
    struct timeval lastacktime;  /* time the last ACK arrived from the remote */
    struct timeval lastsenttime; /* time we sent the last SEQ to the remote */
    u_char gotrfin;                 /* nonzero if we've received a FIN from the remote */
    u_char gotlfin;                 /* nonzero if we've sent a FIN */
    u_char gotrst;                  /* nonzero if an RST has been seen from either side */
    u_int lastrseq;                /* the last sequence number from the remote */
    u_int lastlseq;                /* our last sequence number */
    u_int lastrack;                /* the last ack we sent to the remote */
    u_int lastlack;                /* the last ack we got */
    u_int lfinseq;                 /* the sequence number of our local FIN packet if gotlfin */
    u_int rfinseq;                 /* the sequence number of the FIN from the remote if gotrfin */
    pcap_t **caps;               /* an array of pcap handles of all nterfaces with ipv4 on them */
    u_char lastpktislocal;          /* nonzero if last packet seen was sent by us */
    pcap_t** curcap;            /* current pcap_t handle used by acktrack_next() */
    void *cb;
}acktrack_t;

typedef void (*acktrack_cb_t)(acktrack_t*, sequence_event_t *);

extern "C" PCAPSOCKET_API void _cdecl acktrack_free(acktrack_t *acktrack);
extern "C" PCAPSOCKET_API int _cdecl acktrack_isfinished(acktrack_t *acktrack);
extern "C" PCAPSOCKET_API acktrack_t * _cdecl acktrack_create(int sck);
extern "C" PCAPSOCKET_API void _cdecl acktrack_dispatch(acktrack_t * acktrack, acktrack_cb_t cb);

extern "C" PCAPSOCKET_API int  _cdecl acktrack_openlog(char* logfile);
extern "C" PCAPSOCKET_API void _cdecl acktrack_writelog(char* msg);
extern "C" PCAPSOCKET_API void _cdecl acktrack_closelog(void);
extern "C" PCAPSOCKET_API char* _cdecl acktrack_error(void);

// For VB ...
// Public Declare Ansi Function acktrack_create_fromstrings Lib "acktrack.dll" Alias "acktrack_create_fromstrings" (ByVal LocalEndPointStr As String, ByVal RemoteEndPointStr As String) As IntPtr
// cs = acktrack_create_fromstrings(socket.LocalEndPoint.ToString(), socket.RemoteEndPoint.ToString());
extern "C" PCAPSOCKET_API acktrack_t * _cdecl acktrack_create_fromstrings(char* LocalEndPointStr, char* RemoteEndPointStr);
extern "C" PCAPSOCKET_API sequence_event_t * _cdecl acktrack_next(acktrack_t * acktrack);
extern "C" PCAPSOCKET_API long _cdecl acktrack_se_ts_sec(sequence_event_t *se);
extern "C" PCAPSOCKET_API long _cdecl acktrack_se_ts_usec(sequence_event_t *se);
extern "C" PCAPSOCKET_API u_int _cdecl acktrack_se_is_local(sequence_event_t *se);
extern "C" PCAPSOCKET_API u_int _cdecl acktrack_se_seqno(sequence_event_t *se);
extern "C" PCAPSOCKET_API u_int _cdecl acktrack_se_is_interesting(sequence_event_t *se);
extern "C" PCAPSOCKET_API u_int _cdecl acktrack_se_is_error(sequence_event_t *se);

