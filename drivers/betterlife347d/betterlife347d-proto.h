/*
 * Betterlife 347d:0302 / 347d:0304 - secure-channel protocol helpers (framing + SM2/SM3/SM4)
 * Transport-agnostic: no USB here. Crypto via OpenSSL 3 (SM2) + GM/T SM3 & SM4.
 *
 * Copyright (C) 2026 huellero project
 * Copyright (C) 2026 Rubén García Sánchez & contributors (bounds & CRC hardening, 347d:0302 MOC support)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <glib.h>
#include <stdint.h>

#define BTL_SESSKEY_LEN 16
#define BTL_NONCE_LEN   16
#define BTL_IMG_W       96
#define BTL_IMG_H       112
#define BTL_IMG_SIZE    (BTL_IMG_W * BTL_IMG_H)   /* 10752, 8bpp */

/* Inner payload begins at this byte offset inside a received frame:
 *   [0]=0xAA [1..4]=len32 [5..20]=nonce16 [21]=0x4C cmd sub 0 0 0 [27..30]=dlen32 [31..]=data */
#define BTL_PAYLOAD_OFFSET 31

/* Build a framed packet into out (needs cap >= 32 + dlen + 15).
 * sesskey == NULL => plaintext body (used for the A0/A1/A2 handshake).
 * nonce16 == NULL => random nonce when encrypted, zero nonce when plaintext.
 * Returns the frame length, or -1 on overflow / RNG failure. */
gssize btl_frame_build (uint8_t       *out,
                        gsize          cap,
                        uint8_t        cmd,
                        uint8_t        sub,
                        const uint8_t *data,
                        gsize          dlen,
                        const uint8_t *sesskey,
                        const uint8_t *nonce16);

/* Verify outer CRC32, decrypt (in place) and locate the payload of a received frame.
 * rl = total received bytes. sesskey == NULL => body is plaintext.
 * On success returns a pointer into resp (the payload) and fills
 * cmd, sub and dlen; returns NULL if the frame is malformed, truncated, or fails CRC/magic. */
const uint8_t *btl_frame_parse (uint8_t       *resp,
                                gsize          rl,
                                const uint8_t *sesskey,
                                uint8_t       *cmd,
                                uint8_t       *sub,
                                uint32_t      *dlen);

/* SM2 ephemeral key-agreement state. */
typedef struct _BtlHandshake BtlHandshake;

/* Generate an ephemeral SM2 keypair. NULL on failure. */
BtlHandshake *btl_handshake_new (void);
void          btl_handshake_free (BtlHandshake *hs);

/* Our public key, 65 bytes: 0x04 || X(32) || Y(32). */
gboolean      btl_handshake_pubkey (BtlHandshake *hs, uint8_t out65[65]);

/* Derive the session key from the A2 response payload, which is
 *   [0x04]? || peerX(32) || peerY(32) || MAC(32) || encSessKey(16).
 * Verifies the MAC. Returns TRUE and fills sesskey on success. */
gboolean      btl_handshake_derive (BtlHandshake  *hs,
                                    const uint8_t *payload,
                                    gsize          len,
                                    uint8_t        sesskey[BTL_SESSKEY_LEN]);
