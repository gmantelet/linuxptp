#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sa.h"

int init_security_association_tables(void)
{
    LIST_INIT(&incoming_sa);
    LIST_INIT(&outgoing_sa);
    return 0;
}

int add_incoming_sa(char *buf, struct ClockIdentity *ci)
{
    struct security_association *sa, *sap, *last;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    memset(sa, 0, sizeof(struct security_association));
    memcpy(&(sa->dst_port), ci, sizeof(struct ClockIdentity));
    sa->dst_port.portNumber = 1;

    sscanf (buf,"%u:%u:%u:%u:%u:%u:%u:%u.%u", sa->src_port.clockIdentity.id[0],
           sa->src_port.clockIdentity.id[1], sa->src_port.clockIdentity.id[2],
           sa->src_port.clockIdentity.id[3], sa->src_port.clockIdentity.id[4],
           sa->src_port.clockIdentity.id[5], sa->src_port.clockIdentity.id[6],
           sa->src_port.clockIdentity.id[7], sa->src_port.portNumber);


    if (incoming_sa.lh_first == NULL)
        LIST_INSERT_HEAD(&incoming_sa, sa, sa_entry);
    else
        for (sap = incoming_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);

    return 0;
}

int add_outgoing_sa(char *buf)
{
    struct security_association *sa, *sap, *last;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    memset(sa, 0, sizeof(struct security_association));
    memset(&(sa->src_port), 255, sizeof(struct PortIdentity));

    sscanf (buf,"%u:%u:%u:%u:%u:%u:%u:%u.%u", sa->dst_port.clockIdentity.id[0],
           sa->dst_port.clockIdentity.id[1], sa->dst_port.clockIdentity.id[2],
           sa->dst_port.clockIdentity.id[3], sa->dst_port.clockIdentity.id[4],
           sa->dst_port.clockIdentity.id[5], sa->dst_port.clockIdentity.id[6],
           sa->dst_port.clockIdentity.id[7], sa->dst_port.portNumber);


    if (outgoing_sa.lh_first == NULL)
        LIST_INSERT_HEAD(&outgoing_sa, sa, sa_entry);
    else
        for (sap = outgoing_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);

    return 0;
}
