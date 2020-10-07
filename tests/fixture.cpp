#include "../acktrack.h"
#include <sys/socket.h>

struct sockaddr *parseendpoint(char* endpoint);

int sck_conn(char *endpoint)
{
    struct sockaddr *sa;
    int s;

    sa = parseendpoint(endpoint);
    switch(sa->sa_family) {
        case AF_INET:
            s = socket(AF_INET, SOCK_STREAM, 0);
            connect(s, sa, sizeof(struct sockaddr_in));
            break;
        case AF_INET6:
            s = socket(AF_INET6, SOCK_STREAM, 0);
            connect(s, sa, sizeof(struct sockaddr_in6));
            break;
        default:
            return -1;
        }
    return s;
}

acktrack_t *acktrack_alloc(void)
{
    acktrack_t *ret;
    ret = (acktrack_t *)malloc(sizeof(acktrack_t));
    printf("%p\n", ret);
    return ret;
}

acktrack_t *acktrack_setaddrs(acktrack_t *acktrack, sockaddr *local, sockaddr *remote)
{
    memcpy(&acktrack->local, local, sizeof(acktrack->local));
    memcpy(&acktrack->remote, remote, sizeof(acktrack->remote));
    return acktrack;
}

acktrack_t *set_lseqorig(acktrack_t* acktrack, u_int new_lseqorig)
{
    acktrack->lseqorig = new_lseqorig;
    return acktrack;
}

acktrack_t *set_rseqorig(acktrack_t* acktrack, u_int new_rseqorig)
{
    acktrack->rseqorig = new_rseqorig;
    return acktrack;
}

acktrack_t *set_local(acktrack_t* acktrack, struct sockaddr *sa)
{
    memcpy(&acktrack->local, sa, sizeof(acktrack->local));
    return acktrack;
}

acktrack_t *set_remote(acktrack_t* acktrack, struct sockaddr *sa)
{
    memcpy(&acktrack->remote, sa, sizeof(acktrack->remote));
    return acktrack;
}

acktrack_t *set_lastrseq(acktrack_t* acktrack, unsigned int new_lastrseq)
{
    acktrack->lastrseq = new_lastrseq;
    return acktrack;
}

acktrack_t *set_lastlseq(acktrack_t* acktrack, unsigned int new_lastlseq)
{
    acktrack->lastlseq = new_lastlseq;
    return acktrack;
}

acktrack_t *set_lastlack(acktrack_t* acktrack, unsigned int new_lastlack)
{
    acktrack->lastlack = new_lastlack;
    return acktrack;
}

acktrack_t *set_lastrack(acktrack_t* acktrack, unsigned int new_lastrack)
{
    acktrack->lastrack = new_lastrack;
    return acktrack;
}

acktrack_t *set_gotrfin(acktrack_t* acktrack, u_char new_gotrfin)
{
    acktrack->gotrfin = new_gotrfin;
    return acktrack;
}

acktrack_t *set_gotlfin(acktrack_t* acktrack, u_char new_gotlfin)
{
    acktrack->gotlfin = new_gotlfin;
    return acktrack;
}

acktrack_t *set_gotrst(acktrack_t* acktrack, u_char new_gotrst)
{
    acktrack->gotrst = new_gotrst;
    return acktrack;
}

acktrack_t *set_lfinseq(acktrack_t* acktrack, u_char new_lfinseq)
{
    acktrack->lfinseq = new_lfinseq;
    return acktrack;
}

acktrack_t *set_rfinseq(acktrack_t* acktrack, u_char new_rfinseq)
{
    acktrack->rfinseq = new_rfinseq;
    return acktrack;
}

acktrack_t *set_lastpktislocal(acktrack_t* acktrack, u_char new_lastpktislocal)
{
    acktrack->lastpktislocal = new_lastpktislocal;
    return acktrack;
}

void printaddr(void *p)
{
    printf("%p\n", p);
}

int main(void)
{
}
