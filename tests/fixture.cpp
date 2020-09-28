#include "../acktrack.h"
#include <sys/socket.h>

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

void printaddr(void *p)
{
    printf("%p\n", p);
}

int main(void)
{
}
