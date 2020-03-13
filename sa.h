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
    struct PortIdentity src_port;
    Octet               src_address[6];
    struct PortIdentity dst_port;
    Octet               dst_address[6];
    UInteger32          replay_counter;
    UInteger16          lifetime_id;
    UInteger16          key_id;
    UInteger16          next_lifetime_id;
    UInteger16          next_key_id;
    Enumeration8        trust_state;
    UInteger16          trust_timer;
    UInteger16          trust_timeout;
    Enumeration8        challenge_state;
    UInteger16          challenge_timer;
    UInteger16          challenge_timeout;
    UInteger32          request_nonce;
    UInteger32          response_nonce;
    int                 challenge_required;
    int                 response_required;
    Enumeration8        type_field;
} PACKED;

#endif
