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


void error(char *msg)
{
    perror(msg);
    exit(0);
}

int getsocketinfo(int sck)
{
    struct sockaddr_in laddr;
    struct sockaddr_in raddr;
    socklen_t len;
    int ret;

    printf("socket id %d\n", sck);

    len = sizeof(raddr);

    ret = getpeername(sck, (struct sockaddr*)&raddr, &len);

    if (ret == -1)
        return -1;

    ret = getsockname(sck, (struct sockaddr*)&laddr, &len);

    if (ret == -1)
        return -1;

    printf("%s:%d -> %s:%d\n", (char*)inet_ntoa(laddr.sin_addr), ntohs(laddr.sin_port), (char*)inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));

/*
    printf("Peer IP address: %s\n", (char*)inet_ntoa(raddr.sin_addr));
    printf("Peer port      : %d\n", ntohs(raddr.sin_port));
    printf("Socket IP address: %s\n", (char*)inet_ntoa(laddr.sin_addr));
    printf("Socket port      : %d\n", ntohs(laddr.sin_port));
*/

    return 0;
}

void showsocketinfo(int sck)
{
    int ret;

    ret = getsocketinfo(sck);
    if (ret == -1)
        if (errno == ENOTCONN)
            printf("Socket isn't connected\n");
        else if (errno == EBADF)
            printf("Bad socket descriptor\n");
        else
            printf("Unknown error\n");
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n, ret;

    struct sockaddr_in serv_addr;
    struct hostent *server;


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

    printf("\npreconnect: ");
    showsocketinfo(sockfd);

    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");


    printf("\npostconnect: ");
    showsocketinfo(sockfd);

    close(sockfd);

    printf("\npostclose: ");
    showsocketinfo(sockfd);

    exit(0);

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
