#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "print.h"
#include "sa.h"

int init_security_association_tables(void)
{
    LIST_INIT(&incoming_sa);
    LIST_INIT(&outgoing_sa);
    pr_info("Security Association Tables initialized");
    return 0;
}

int add_incoming_sa(char *buf, struct ClockIdentity *ci)
{
    struct security_association *sa, *sap, *last;
    unsigned char cid[8] = {0};
    unsigned char add[6];
    unsigned int pnum = 0;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    if(15 != sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx.%x,%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c",
        &cid[0], &cid[1], &cid[2], &cid[3], &cid[4], &cid[5], &cid[6], &cid[7], &pnum, &add[0], &add[1], &add[2], &add[3], &add[4], &add[5]))
    {
      pr_err("Failed to parse incoming SA string");
      return -2;
    }

    memset(sa, 0, sizeof(struct security_association));
    memcpy(&(sa->dst_port), ci, sizeof(struct ClockIdentity));
    memset(&(sa->dst_address), 255, 6);
    sa->dst_port.portNumber = 1;
    memcpy(&(sa->src_port), cid, sizeof(struct PortIdentity));
    sa->src_port.portNumber = pnum;
    memcpy(&(sa->src_address), add, sizeof(add));

    if (incoming_sa.lh_first == NULL)
    {
        LIST_INSERT_HEAD(&incoming_sa, sa, sa_entry);
        pr_info("List insert head...");
    }
    else
    {
        for (sap = incoming_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);
        pr_info("List insert after...");
    }

    return 0;
}

void add_dynamic_sa(struct security_association *sa, struct PortIdentity *src_port, char *src_add, struct PortIdentity *dst_port)
{
    struct security_association *sap, *last;

    memset(sa, 0, sizeof(struct security_association));
    memcpy(&(sa->dst_port), dst_port, sizeof(struct PortIdentity));
    memset(&(sa->dst_address), 255, 6);
    memcpy(&(sa->src_port), src_port, sizeof(struct PortIdentity));
    memcpy(&(sa->src_address), src_add, 6);

    if (incoming_sa.lh_first == NULL)
    {
        LIST_INSERT_HEAD(&incoming_sa, sa, sa_entry);
        pr_info("List insert head...");
    }
    else
    {
        for (sap = incoming_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);
        pr_info("List insert after...");
    }
}

int add_outgoing_sa(char *buf)
{
    struct security_association *sa, *sap, *last;
    unsigned char cid[8] = {0};
    unsigned char add[6];
    unsigned int pnum = 0;

    if ((sa = malloc(sizeof(struct security_association))) == NULL)
        return -1;  // Memory allocation error

    if(15 != sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx.%x,%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c",
        &cid[0], &cid[1], &cid[2], &cid[3], &cid[4], &cid[5], &cid[6], &cid[7], &pnum, &add[0], &add[1], &add[2], &add[3], &add[4], &add[5]))
    {
      pr_err("Failed to parse incoming SA string");
      return -2;
    }

    memset(sa, 0, sizeof(struct security_association));
    memset(&(sa->src_port), 255, sizeof(struct PortIdentity));
    memset(&(sa->src_address), 255, 6);
    memcpy(&(sa->dst_port), cid, sizeof(struct PortIdentity));
    sa->dst_port.portNumber = pnum;
    memcpy(&(sa->dst_address), add, sizeof(add));

    if (outgoing_sa.lh_first == NULL)
    {
        LIST_INSERT_HEAD(&outgoing_sa, sa, sa_entry);
        pr_info("List insert head...");
    }
    else
    {
        for (sap = outgoing_sa.lh_first; sap != NULL; sap = sap->sa_entry.le_next)
            last = sap;

        LIST_INSERT_AFTER(last, sa, sa_entry);
        pr_info("List insert after...");
    }
    return 0;
}

static int is_wildcard(struct PortIdentity *pi, int len)
{
    unsigned char *ch = (unsigned char *)pi;
    while(--len > 0 && ch[len] == 255);
    return (len != 0)? 0: 1;
}

struct security_association* get_incoming_sa(struct PortIdentity *src_port, char *src_add, struct PortIdentity *dst_port)
{
    struct security_association *sa = NULL;

    //unsigned char *ch = (unsigned char *) src_port;
    //pr_info("Msg src Port Identity: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x.%02x%02x", ch[0], ch[1], ch[2], ch[3], ch[4], ch[5], ch[6], ch[7], ch[8], ch[9]);
    //pr_info("Msg src Address      : %02x:%02x:%02x:%02x:%02x:%02x", src_add[0], src_add[1], src_add[2], src_add[3], src_add[4], src_add[5]);

    for (sa = incoming_sa.lh_first; sa != NULL; sa = sa->sa_entry.le_next)
    {

        //unsigned char *c2 = (unsigned char *) &(sa->src_port);
    	//pr_info("SA src Port Identity: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x.%02x%02x", c2[0], c2[1], c2[2], c2[3], c2[4], c2[5], c2[6], c2[7], c2[8], c2[9]);
        //pr_info("SA src Address      : %02x:%02x:%02x:%02x:%02x:%02x", sa->src_address[0], sa->src_address[1], sa->src_address[2], sa->src_address[3], sa->src_address[4], sa->src_address[5]);
 
        if (!memcmp(&(sa->src_port), src_port, sizeof(struct PortIdentity)) &&
            //!memcmp(sa->src_address, src_add, 6) &&
            !memcmp(&(sa->dst_port), dst_port, sizeof(struct PortIdentity)))
            return sa;
    }

    return NULL;
}

struct security_association* get_outgoing_sa(struct PortIdentity *src_port)
{
    struct security_association *sa = NULL;

    for (sa = outgoing_sa.lh_first; sa != NULL; sa = sa->sa_entry.le_next)
    {
        // If the SA we read is wildcard, we automatically use this one.
        if (is_wildcard(&(sa->dst_port), sizeof(sa->dst_port)))
            return sa;

        if (!memcmp(&(sa->src_port), src_port, sizeof(struct PortIdentity)))
            return sa;
    }

    return NULL;
}
