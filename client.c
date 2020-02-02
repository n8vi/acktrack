#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/select.h>

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

pcap_t **capsck_openallinterfaces(char* errbuf)
{
    pcap_addr_t *a;
    pcap_if_t *alldevs;
    pcap_if_t *ipv4devs;
    pcap_if_t *d;
    pcap_if_t *m = NULL;
    pcap_if_t *f = NULL;
    pcap_if_t *p = NULL;
    int i=0;
    int c=0;
    int has_ipv4_addr;
    pcap_t **descr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

    for (d=alldevs; d != NULL; d = d->next) {
        has_ipv4_addr = 0;
        for(a=d->addresses; a; a=a->next) {
            if (a->addr->sa_family == AF_INET)
                has_ipv4_addr = 1;
            }
        if (! has_ipv4_addr)
            continue;

        p = m;
        m = malloc(sizeof(pcap_if_t));
        memcpy(m,d,sizeof(d));
        m->next = NULL;
        p->next = m;
        if (!f)
            f = m;
        c++;
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
        descr[i] = pcap_open_live(d->name, BUFSIZ, 0, -1,errbuf);
        i++;
        }

    descr[i] = NULL;

    printf("good so far\n");


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
    static pcap_t *descr[2] = {NULL,NULL};
    // pcap_t **descr;
    // descr[0] = pcap_open_live("any", BUFSIZ, 0, -1,errbuf);
    struct pcap_pkthdr hdr;
    const u_char *packet;
    const char source[50];
    const char dest[50];
    const char filter[100];
    struct bpf_program fp;
    bpf_u_int32 pNet;
    bpf_u_int32 pMask;

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

        return descr;
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

        return descr;
        }

    // to make this work on windows it may be necessary to get an interface list with pcap_findalldevs_ex()
    // and pcap_open_live all interfaces, unless "any" is present (at which point we know it's linux)
    // Why not check the routing table and pick the interface based on that you ask?  INBOUND packets are not
    // bound to the rules of OUR routing table, they can come from literally anywhere.  Also, that sounds like
    // a lot more work.

    // descr = capsck_openallinterfaces(errbuf); 


    descr[0] = pcap_open_live("any", BUFSIZ, 0, -1,errbuf);
    descr[1] = NULL;

    if(descr[0] == NULL)
    {
        strcpy(errbuf, "pcap_compile failed");
        return descr;
    }

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

    pcap_lookupnet("any", &pNet, &pMask, errbuf);

    // compile the filter string we built above into a BPF binary.  The string, by the way, can be tested with
    // tshark or wireshark
    // printf("PCAP filter: %s\n", filter)
    if(pcap_compile(descr[0], &fp, filter, 0, pNet) == -1) {
        strcpy(errbuf, "pcap_compile failed");
        return NULL;
        }

    // Load the compiled filter into the kernel
    if(pcap_setfilter(descr[0], &fp) == -1){
        strcpy(errbuf, "pcap_setfilter failed");
        return NULL;
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
    int sockfd, portno, n, ret;

    char errbuf[PCAP_ERRBUF_SIZE];
    struct sockaddr_in serv_addr;
    struct hostent *server;
    pcap_t **capsck;
    struct timeval t;
    int i;


/*
    capsck_openallinterfaces(errbuf);
    exit(0);
*/
    


    char buffer[256];
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
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

    if (capsck[0] == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(0);
        }

    // Perhaps in a thread?
    while (1) {
        capsck_dispatch(capsck);
        t.tv_sec = 0;
        t.tv_usec = 500;
        select(0,NULL,NULL,NULL, &t);
        i++;
        i %= 100;
        if (i == 0) {
            printf("normal thing-doing loop here\n");
            }
        }
        
	
    // You can ignore the stuff below, it's pasted from a sockets programming client example, as is a lot
    // of the code above.  The infinite loop above currently ensures this code is never reached, but I'll 
    // leave it here in case you'd like to play with it.  In my Makefile, I have a "make test" target that
    // contacts an irc server, since those are chatty immediately without requiring I send them anything.
    // The code below is likely to confuse an irc server.

    printf("Please enter the message: ");
    bzero(buffer,256);
    fgets(buffer,255,stdin);
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) 
         error("ERROR writing to socket");
    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) 
         error("ERROR reading from socket");
    printf("%s\n",buffer);
    return 0;
}
