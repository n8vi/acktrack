#include "acktrack.h"
#include <stdio.h>

#define LOGFILE "/tmp/acktrack.log"

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1

void error(char* msg)
{
    perror(msg);
    exit(1);
}


void printpkt(sequence_event_t* se)
{
    static int seqno = 8;
    static int ackno = 8;

    if (acktrack_se_is_interesting(se)) {
        if (acktrack_se_is_local(se)) {
            printf("  --> SEQ %lu.%lu: %d\n", acktrack_se_ts_sec(se), acktrack_se_ts_usec(se), acktrack_se_seqno(se));
            if (seqno > acktrack_se_seqno(se) || acktrack_se_seqno(se) > 9){
                printf("PACKET OUT OF SEQUENCE\n");
                exit(1);
                }
            seqno = acktrack_se_seqno(se);
        } else {
            printf("  <-- ACK %lu.%lu: %d\n", acktrack_se_ts_sec(se), acktrack_se_ts_usec(se), acktrack_se_seqno(se));
            if (ackno > acktrack_se_seqno(se) || acktrack_se_seqno(se) > 9) {
                printf("PACKET OUT OF SEQUENCE\n");
                exit(1);
                }
            ackno = acktrack_se_seqno(se);
        }
    }
}


int main(int argc, char* argv[])
{

#ifndef WIN32
    int sockfd;
#else
    SOCKET sockfd;
#endif

    int portno, n; // , ret;
    struct sockaddr_in serv_addr;
    struct hostent* server;
    acktrack_t* acktrack;
    // struct timeval t;
    int i = 0;
    char buffer[256];

    struct addrinfo hints, *res;

    int iResult;

#ifdef LOGFILE
    printf("opening log\n");
    acktrack_openlog(LOGFILE);
    printf("opened log\n");
#endif

#ifdef WIN32
    WSADATA wsaData;
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // printf("\n\n");

    if (argc < 3) {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }
    // portno = atoi(argv[2]);

    memset(&hints, 0, sizeof(hints));

    hints.ai_socktype = SOCK_STREAM;

    iResult = getaddrinfo(argv[1], argv[2], &hints, &res);

    if (iResult) {
        perror("getaddrinfo()");
        exit(1);
        }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd < 0)
        error((char*)"ERROR opening socket");

    printf("Connecting to host %s port %s\n", argv[1], argv[2]);


/*
    bzero((char*)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = res->ai_family;
    bcopy((char*)server->h_addr,
        (char*)&serv_addr.sin_addr.s_addr,
        server->h_length);
    serv_addr.sin_port = htons(portno);
*/

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
        error((char*)"ERROR connecting");

    acktrack = acktrack_create(sockfd);

    printf("connected ... \n");
    // sleep (5);

    if (acktrack == NULL) {
        fprintf(stderr, "acktrack_create() failed.\n");
        exit(1);
    }

    strcpy(buffer, "GET /\r\n");
    n = send(sockfd, buffer, strlen(buffer), 0);
    if (n < 0)
        error((char*)"ERROR writing to socket");

    while (1) {
        n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (n < 0)
            error((char*)"ERROR reading from socket");
        if (n > 0) {
            // acktrack_dispatch(acktrack, mycallback);
            printpkt(acktrack_next(acktrack));            
            // printf("read %d octets\n", n);
        }
        if (n == 0) {
            printf("Connection closed\n");
            // acktrack_dispatch(acktrack, mycallback);
            printpkt(acktrack_next(acktrack));
#ifdef WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            while (!acktrack_isfinished(acktrack))
                // acktrack_dispatch(acktrack, mycallback);
                printpkt(acktrack_next(acktrack));
            return 0;
        }
        i++;
        i %= 100;
        // if (i == 0) printf("normal thing-doing loop here (last read %d)\n", n);
    }

}
