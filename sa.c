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
    unsigned char cid[8] = {0};
    unsigned int pnum = 0;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    sscanf (buf,"%hhu:%hhu:%hhu:%hhu:%hhu:%hhu:%hhu:%hhu.%u", cid, cid + 1, cid + 2, cid + 3,
            cid + 4, cid + 5, cid + 6, cid + 7, &pnum);

    memset(sa, 0, sizeof(struct security_association));
    memcpy(&(sa->dst_port), ci, sizeof(struct ClockIdentity));
    sa->dst_port.portNumber = 1;
    memcpy(&(sa->src_port), cid, sizeof(struct PortIdentity));
    sa->src_port.portNumber = pnum;

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
    unsigned char cid[8] = {0};
    unsigned int pnum = 0;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    sscanf (buf,"%hhu:%hhu:%hhu:%hhu:%hhu:%hhu:%hhu:%hhu.%u", cid, cid + 1, cid + 2, cid + 3,
            cid + 4, cid + 5, cid + 6, cid + 7, &pnum);

    memset(sa, 0, sizeof(struct security_association));
    memset(&(sa->src_port), 255, sizeof(struct PortIdentity));
    memcpy(&(sa->dst_port), cid, sizeof(struct PortIdentity));
    sa->dst_port.portNumber = pnum;

    if (outgoing_sa.lh_first == NULL)
        LIST_INSERT_HEAD(&outgoing_sa, sa, sa_entry);
    else
        for (sap = outgoing_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);

    return 0;
}
