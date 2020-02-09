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
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif


void error(char *msg)
{
    perror(msg);
    exit(0);
}

void capsck_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
  static int count = 1;

  printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}

pcap_t **capsck_openallinterfaces(char *filter, char* errbuf)
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


    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        // printf("%s ...\n", d->name);
        has_ipv4_addr = 0;
        for(a=d->addresses; a; a=a->next) {
            if (a->addr->sa_family == AF_INET)
                has_ipv4_addr = 1;
            }
        if (! has_ipv4_addr) {
            // printf("  %s has no ipv4\n", d->name);
            continue;
            }

        printf("  %s has ipv4.  Copying to new list ...\n", d->name);

        p = m;
        m = malloc(sizeof(pcap_if_t));
        memcpy(m,d,sizeof(pcap_if_t));
        m->next = NULL;
        if (p)
            p->next = m;
        if (!f)
            f = m;
        c++;

        printf("  %s has ipv4.  Copied to %s\n", d->name, m->name);
/*       
        printf("%d. %s\n", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf("no descr\n");
*/
        }

    descr = malloc(sizeof(pcap_t *) * (c+1));
    i = 0;

    for (d=f; d!= NULL; d = d->next) {
        printf("pcap_open_live(%s)\n", d->name);
        descr[i] = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);

        if(descr[i] == NULL) {
            sprintf(errbuf, "pcap_open_live failed for interface %s", d->name);
            descr[0] = NULL;
            /* ACTUALLY DEALLOCATE HERE */
            return NULL;
            }

        /* next step happens here */
        /* need to either pass filter string in here, or combine both functions */
    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
    // printf("PCAP filter: %s\n", filter)
        if (pcap_compile(descr[i], &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            strcpy(errbuf, "pcap_compile failed");
            return NULL;
        }

        // Load the compiled filter into the kernel
        if (pcap_setfilter(descr[i], &fp) == -1) {
            strcpy(errbuf, "pcap_setfilter failed");
            return NULL;
        }

        i++;
        }

    descr[i] = NULL;


    /* [x] 1) count interfaces and place into another linked list */
    /* [x] 2) allocate enough memory for array based on count */
    /* [x] 3) unwind linked list into array of newly opened pcap handles */
    /* [ ] 4) properly deallocate all linked lists!  */

    pcap_freealldevs(alldevs);

    return(descr);

}
    
pcap_t **capsck_create(int sck, char* errbuf)
{
    struct sockaddr_in laddr;
    struct sockaddr_in raddr;
    socklen_t len;
    int ret;
    pcap_t **descr;
    const char source[50];
    const char dest[50];
    const char filter[100];
    char type;
    int typelen;

    ret = getsockopt(sck, SOL_SOCKET, SO_TYPE, &type, &typelen);

    if (ret == -1) {
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

    if (type != SOCK_STREAM) {
        strcpy(errbuf, "Socket is not TCP");
        return NULL;
    }

    len = sizeof(raddr);

    ret = getpeername(sck, (struct sockaddr*)&raddr, &len);

    if (ret == -1) {
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

    ret = getsockname(sck, (struct sockaddr*)&laddr, &len);

    if (ret == -1) {
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


    sprintf((char*)source, "src host %s and src port %d", 
        (char*)inet_ntoa(raddr.sin_addr), 
        ntohs(raddr.sin_port)
        );

    sprintf((char*)dest, "dst host %s and dst port %d", 
        (char*)inet_ntoa(laddr.sin_addr), 
        ntohs(laddr.sin_port)
        );

    // inet_ntoa returns a static buffer so we can't just do this all at once 
    sprintf((char *)filter, "%s and %s", source, dest);

    descr = capsck_openallinterfaces((char *)filter, errbuf);

    if (descr == NULL)
    {
        // strcpy(errbuf, "capsck_openallinterfaces failed");
        return descr;
    }


    return descr;
}

void capsck_dispatch(pcap_t **descr)
{
    // to make this work on windows it may be necessary to pcap_dispatch() the entire list of interfaces.
    // See comments above next to pcap_open_live()

    while(*descr) {
        pcap_dispatch(*descr, -1, capsck_callback, NULL);
        descr++;
        }
}

int main(int argc, char *argv[])
{

#ifndef WIN32
    int sockfd;
#else
    SOCKET sockfd;
#endif
    
    int portno, n; // , ret;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    pcap_t **capsck;
    // struct timeval t;
    int i = 0;
    char buffer[256];
 
    int iResult;

#ifdef WIN32
    WSADATA wsaData;
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif
 
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    printf("Connecting to host %s port %d\n", argv[1], portno);
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    capsck = capsck_create(sockfd, errbuf);

    if (capsck == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(0);
        }

    strcpy(buffer, "GET /\r\n");
    printf("writing\n");
    n = send(sockfd, buffer, strlen(buffer),0);
    printf("wrote\n");
    if (n < 0)
        error("ERROR writing to socket");


    // Perhaps in a thread?
    while (1) {
        // n = read(sockfd, buffer, 255);
        n = recv(sockfd, buffer, sizeof(buffer)-1, 0);
        if (n < 0)
            error("ERROR reading from socket");
        if (n > 0)
            printf("read %d octets\n", n);
        if (n == 0) {
            printf("Connection closed\n");
            return(0);
        }
        // printf("%s\n", buffer);
        capsck_dispatch(capsck);
/*
#ifdef WIN32
        Sleep(50);
#else
        t.tv_sec = 0;
        t.tv_usec = 50000;
        select(0,NULL,NULL,NULL, &t);
#endif
*/
        i++;
        i %= 100;
        if (i == 0) {
            printf("normal thing-doing loop here (last read %d)\n", n);
            }
        }
        
}
