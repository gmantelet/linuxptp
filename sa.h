/**
 * @file sa.h
 * @brief Implements the various Security Association types.
 * @note Copyright (C) 2019 Guillaume Mantelet <gmantelet@voltigeurnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef HAVE_SA_H
#define HAVE_SA_H


enum TrustState
{
    UNTRUSTED,
    TRUSTED,
    NO_MATCHING_SA,
};

enum ChallengeState
{
    IDLE,
    CHALLENGING,
};

enum SATypeField
{
    STATIC,
    DYNAMIC,
};


struct security_association
{
    LIST_ENTRY(security_association)    sa_entry;
    struct PortIdentity                 src_port;
    struct PortIdentity                 dst_port;
    UInteger32                          replay_counter;
    UInteger16                          lifetime_id;
    UInteger16                          key_id;
    UInteger16                          next_lifetime_id;
    UInteger16                          next_key_id;
    Enumeration8                        trust_state;
    UInteger16                          trust_timer;
    UInteger16                          trust_timeout;
    Enumeration8                        challenge_state;
    UInteger16                          challenge_timer;
    UInteger16                          challenge_timeout;
    UInteger32                          request_nonce;
    UInteger32                          response_nonce;
    int                                 challenge_required;
    int                                 response_required;
    Enumeration8                        type_field;
} PACKED;


LIST_HEAD(incoming_sa_list, security_association) incoming_sa;
LIST_HEAD(outgoing_sa_list, security_association) outgoing_sa;

int init_security_association_tables(void);
int add_incoming_sa(char *buf, );
int add_outgoing_sa(char *buf);

// LIST_INIT(&key_head);
//
// k1 = malloc(sizeof(struct key));      // Insert at the head
// LIST_INSERT_HEAD(&key_head, k1, key_entries);
//
// k2 = malloc(sizeof(struct key));      // Insert after
// LIST_INSERT_AFTER(k1, k2, key_entries);
//
// for (kp = key_head.lh_first; kp != NULL; kp = kp->key_entries.le_next)  // Forward traversal
//    np-> ...
//
//  while (key_head.lh_first != NULL)           // Delete.
//    LIST_REMOVE(key_head.lh_first, key_entries);
#endif
