/**
 * @file key.h
 * @brief Implements the keystore for PTP security.
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
#ifndef HAVE_KEY_H
#define HAVE_KEY_H

#include <sys/queue.h>
#include "tmv.h"


struct key {
    LIST_ENTRY(key)  key_entries;
    UInteger16       key_id;
    UInteger8        algorithm_id;
    Octet            security_key[32];
    struct Timestamp startTime;
    struct Timestamp expirationTime;
    int              valid;
};

struct key_store
{
    LIST_HEAD(key_list, key) key_head;
    struct key_head *key_list;  // List head.
};

struct key* get_key(UInteger16 key_id);
void fetch_key(void);

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
