#include "pcapsocket.h"
#include <stdio.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1

void error(char* msg)
{
    perror(msg);
    exit(0);
}


void printpkt(sequence_event_t* se)
{
    if (se->is_interesting) {
        if (se->is_local) {
            printf("  <-- SEQ %lu.%lu: %d\n", se->ts.tv_sec, se->ts.tv_usec, se->seqno);
        }
        else {
            printf("  --> ACK %lu.%lu: %d\n", se->ts.tv_sec, se->ts.tv_usec, se->seqno);
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
    capsck_t* capsck;
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

    printf("\n\n");

    if (argc < 3) {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error((char*)"ERROR opening socket");

    printf("Connecting to host %s port %d\n", argv[1], portno);
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char*)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char*)server->h_addr,
        (char*)&serv_addr.sin_addr.s_addr,
        server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd, (struct sockaddr*) & serv_addr, sizeof(serv_addr)) < 0)
        error((char*)"ERROR connecting");

    capsck = capsck_create(sockfd);

    printf("connected ... \n");
    // sleep (5);

    if (capsck == NULL) {
        fprintf(stderr, "capsck_create() failed.\n");
        exit(0);
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
            // capsck_dispatch(capsck, mycallback);
            printpkt(capsck_next(capsck));            
            // printf("read %d octets\n", n);
        }
        if (n == 0) {
            printf("Connection closed\n");
            // capsck_dispatch(capsck, mycallback);
            printpkt(capsck_next(capsck));
#ifdef WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            while (!capsck_isfinished(capsck))
                // capsck_dispatch(capsck, mycallback);
                printpkt(capsck_next(capsck));
            return 0;
        }
        i++;
        i %= 100;
        // if (i == 0) printf("normal thing-doing loop here (last read %d)\n", n);
    }

}