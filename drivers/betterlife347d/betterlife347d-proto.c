/*
 * Betterlife 347d:0302 / 347d:0304 - secure-channel protocol helpers (framing + SM2/SM3/SM4)
 *
 * Copyright (C) 2026 huellero project
 * Copyright (C) 2026 Rubén García Sánchez & contributors (bounds & CRC hardening, 347d:0302 MOC support)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Frame layout (little-endian lengths):
 *   0xAA | len32 | nonce16 | body | crc32(reflected 0xEDB88320)
 * where len = 16 + body_len + 4, and
 *   body = 0x4C | cmd | sub | 0 0 0 | dlen32 | data | pad-to-16.
 * When a session key is set, body is SM4-ECB encrypted under a per-frame key
 *   framekey = SM4-ECB-encrypt(sesskey, nonce16).
 * Handshake: SM2 ECDH, KDF = SM3(Sx||Sy||00000001), sess = encSess ^ KDF,
 *   MAC = SM3(Sx||sess||Sy).
 */

#include "betterlife347d-proto.h"
#include "sm3.h"
#include "sm4.h"

#include <string.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* SM2 needs the OpenSSL 3 low-level EC API to recover the full shared point
 * (both X and Y); EVP_PKEY_derive only exposes X. These calls are flagged
 * deprecated-in-favour-of-EVP but remain supported. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/ec.h>
#include <openssl/bn.h>

/* SM2 recommended curve parameters, GM/T 0003.5-2012 (big-endian hex). */
#define SM2_P  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define SM2_A  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define SM2_B  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define SM2_GX "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define SM2_GY "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
#define SM2_N  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"

static EC_GROUP *
sm2_group_new (BN_CTX *ctx)
{
  BIGNUM *p = NULL, *a = NULL, *b = NULL, *gx = NULL, *gy = NULL, *n = NULL;
  EC_GROUP *g = NULL;
  EC_POINT *gen = NULL;

  if (!BN_hex2bn (&p, SM2_P) || !BN_hex2bn (&a, SM2_A) || !BN_hex2bn (&b, SM2_B) ||
      !BN_hex2bn (&gx, SM2_GX) || !BN_hex2bn (&gy, SM2_GY) || !BN_hex2bn (&n, SM2_N))
    goto out;

  g = EC_GROUP_new_curve_GFp (p, a, b, ctx);
  if (!g)
    goto out;

  gen = EC_POINT_new (g);
  if (!gen ||
      EC_POINT_set_affine_coordinates (g, gen, gx, gy, ctx) != 1 ||
      EC_GROUP_set_generator (g, gen, n, BN_value_one ()) != 1)
    {
      EC_GROUP_free (g);
      g = NULL;
    }

out:
  BN_free (p); BN_free (a); BN_free (b);
  BN_free (gx); BN_free (gy); BN_free (n);
  EC_POINT_free (gen);
  return g;
}

static uint32_t
crc32f (const uint8_t *p, gsize n)
{
  uint32_t c = 0xffffffffu;

  for (gsize i = 0; i < n; i++)
    {
      c ^= p[i];
      for (int k = 0; k < 8; k++)
        c = (c >> 1) ^ (0xEDB88320u & -(c & 1));
    }
  return ~c;
}

static void
sm4_ecb (const uint8_t key[16], const uint8_t *in, uint8_t *out, int nblocks, int enc)
{
  uint32_t rk[32];

  sm4_key_schedule (key, rk, enc);
  for (int i = 0; i < nblocks; i++)
    sm4_crypt_block (rk, in + i * 16, out + i * 16);
  OPENSSL_cleanse (rk, sizeof rk);
}

gssize
btl_frame_build (uint8_t *out, gsize cap, uint8_t cmd, uint8_t sub,
                 const uint8_t *data, gsize dlen,
                 const uint8_t *sesskey, const uint8_t *nonce16)
{
  int pad = (16 - ((dlen + 10) & 15)) & 15;
  gsize blen = 10 + dlen + pad;             /* always a multiple of 16 */
  gsize crcoff = 21 + blen;
  gsize total = crcoff + 4;
  uint8_t *body = out + 21;
  uint32_t len, crc;

  if (dlen > G_MAXUINT32 - 32 || total > cap)
    return -1;

  out[0] = 0xAA;
  if (sesskey)
    {
      if (nonce16)
        memcpy (out + 5, nonce16, 16);
      else if (RAND_bytes (out + 5, 16) != 1)
        return -1;
    }
  else
    {
      memset (out + 5, 0, 16);
    }

  memset (body, 0, blen);
  body[0] = 0x4C;
  body[1] = cmd;
  body[2] = sub;
  body[6] = (uint8_t) (dlen & 0xff);
  body[7] = (uint8_t) ((dlen >> 8) & 0xff);
  body[8] = (uint8_t) ((dlen >> 16) & 0xff);
  body[9] = (uint8_t) ((dlen >> 24) & 0xff);
  if (data && dlen)
    memcpy (body + 10, data, dlen);

  if (sesskey)
    {
      uint8_t fk[16];
      sm4_ecb (sesskey, out + 5, fk, 1, 1);
      sm4_ecb (fk, body, body, (int) (blen / 16), 1);
      OPENSSL_cleanse (fk, sizeof fk);
    }

  len = (uint32_t) (16 + blen + 4);
  out[1] = (uint8_t) (len & 0xff);
  out[2] = (uint8_t) ((len >> 8) & 0xff);
  out[3] = (uint8_t) ((len >> 16) & 0xff);
  out[4] = (uint8_t) ((len >> 24) & 0xff);

  crc = crc32f (out, crcoff);
  out[crcoff] = (uint8_t) (crc & 0xff);
  out[crcoff + 1] = (uint8_t) ((crc >> 8) & 0xff);
  out[crcoff + 2] = (uint8_t) ((crc >> 16) & 0xff);
  out[crcoff + 3] = (uint8_t) ((crc >> 24) & 0xff);
  return (gssize) total;
}

const uint8_t *
btl_frame_parse (uint8_t *resp, gsize rl, const uint8_t *sesskey,
                 uint8_t *cmd, uint8_t *sub, uint32_t *dlen)
{
  uint32_t len, rx_crc, calc_crc, inner_dlen;
  gsize total, blen, crcoff;
  uint8_t *body = resp + 21;

  if (rl < BTL_PAYLOAD_OFFSET + 4 || resp[0] != 0xAA)
    return NULL;

  len = (uint32_t) resp[1] |
        ((uint32_t) resp[2] << 8) |
        ((uint32_t) resp[3] << 16) |
        ((uint32_t) resp[4] << 24);
  total = (gsize) len + 5;
  if (len < 20 || total > rl)
    return NULL;

  blen = len - 20;
  if (blen < 16 || (blen & 15))
    return NULL;

  crcoff = total - 4;
  rx_crc = (uint32_t) resp[crcoff] |
           ((uint32_t) resp[crcoff + 1] << 8) |
           ((uint32_t) resp[crcoff + 2] << 16) |
           ((uint32_t) resp[crcoff + 3] << 24);
  calc_crc = crc32f (resp, crcoff);
  if (rx_crc != calc_crc)
    return NULL;

  if (sesskey)
    {
      uint8_t fk[16];
      sm4_ecb (sesskey, resp + 5, fk, 1, 1);
      sm4_ecb (fk, body, body, (int) (blen / 16), 0);
      OPENSSL_cleanse (fk, sizeof fk);
    }

  if (resp[21] != 0x4C)
    return NULL;

  inner_dlen = (uint32_t) resp[27] |
               ((uint32_t) resp[28] << 8) |
               ((uint32_t) resp[29] << 16) |
               ((uint32_t) resp[30] << 24);
  if ((gsize) inner_dlen > blen - 10)
    return NULL;

  if (cmd)
    *cmd = resp[22];
  if (sub)
    *sub = resp[23];
  if (dlen)
    *dlen = inner_dlen;

  return resp + BTL_PAYLOAD_OFFSET;
}

struct _BtlHandshake
{
  EC_GROUP *group;
  BIGNUM   *d;
  BN_CTX   *ctx;
};

void
btl_handshake_free (BtlHandshake *hs)
{
  if (!hs)
    return;
  if (hs->d)
    BN_clear_free (hs->d);
  if (hs->group)
    EC_GROUP_free (hs->group);
  if (hs->ctx)
    BN_CTX_free (hs->ctx);
  g_free (hs);
}

BtlHandshake *
btl_handshake_new (void)
{
  BtlHandshake *hs = g_new0 (BtlHandshake, 1);
  const BIGNUM *n;

  hs->ctx = BN_CTX_new ();
  hs->group = hs->ctx ? sm2_group_new (hs->ctx) : NULL;
  hs->d = BN_new ();
  if (!hs->ctx || !hs->group || !hs->d)
    goto fail;

  n = EC_GROUP_get0_order (hs->group);
  do
    {
      if (!BN_rand_range (hs->d, n))
        goto fail;
    }
  while (BN_is_zero (hs->d));
  return hs;

fail:
  btl_handshake_free (hs);
  return NULL;
}

gboolean
btl_handshake_pubkey (BtlHandshake *hs, uint8_t out65[65])
{
  EC_POINT *q = EC_POINT_new (hs->group);
  BIGNUM *x = BN_new (), *y = BN_new ();
  gboolean ok = q && x && y &&
                EC_POINT_mul (hs->group, q, hs->d, NULL, NULL, hs->ctx) == 1 &&
                EC_POINT_get_affine_coordinates (hs->group, q, x, y, hs->ctx) == 1;

  if (ok)
    {
      out65[0] = 0x04;
      BN_bn2binpad (x, out65 + 1, 32);
      BN_bn2binpad (y, out65 + 33, 32);
    }
  EC_POINT_free (q);
  BN_free (x);
  BN_free (y);
  return ok;
}

gboolean
btl_handshake_derive (BtlHandshake *hs, const uint8_t *payload, gsize len,
                      uint8_t sesskey[BTL_SESSKEY_LEN])
{
  gsize off = (len > 0 && payload[0] == 0x04) ? 1 : 0;
  const uint8_t *mx_b, *my_b, *mac, *enc;
  BIGNUM *mx = NULL, *my = NULL, *sx = BN_new (), *sy = BN_new ();
  EC_POINT *qm = EC_POINT_new (hs->group), *s = EC_POINT_new (hs->group);
  uint8_t sxb[32], syb[32], kd[32], sk[16], z[68], m[80], mo[32];
  gboolean ok;

  if (len < off + 64 + 32 + 16)
    { ok = FALSE; goto out; }

  mx_b = payload + off;
  my_b = payload + off + 32;
  mac = payload + off + 64;
  enc = payload + off + 96;

  mx = BN_bin2bn (mx_b, 32, NULL);
  my = BN_bin2bn (my_b, 32, NULL);
  ok = mx && my && sx && sy && qm && s &&
       EC_POINT_set_affine_coordinates (hs->group, qm, mx, my, hs->ctx) == 1 &&
       EC_POINT_is_on_curve (hs->group, qm, hs->ctx) == 1 &&
       EC_POINT_mul (hs->group, s, NULL, qm, hs->d, hs->ctx) == 1 &&
       EC_POINT_get_affine_coordinates (hs->group, s, sx, sy, hs->ctx) == 1;
  if (!ok)
    goto out;

  BN_bn2binpad (sx, sxb, 32);
  BN_bn2binpad (sy, syb, 32);

  memcpy (z, sxb, 32);
  memcpy (z + 32, syb, 32);
  z[64] = 0; z[65] = 0; z[66] = 0; z[67] = 1;
  sm3 (z, 68, kd);

  for (int i = 0; i < 16; i++)
    sk[i] = enc[i] ^ kd[i];

  memcpy (m, sxb, 32);
  memcpy (m + 32, sk, 16);
  memcpy (m + 48, syb, 32);
  sm3 (m, 80, mo);
  ok = CRYPTO_memcmp (mo, mac, 32) == 0;
  if (ok)
    memcpy (sesskey, sk, BTL_SESSKEY_LEN);

out:
  OPENSSL_cleanse (sxb, sizeof sxb);
  OPENSSL_cleanse (syb, sizeof syb);
  OPENSSL_cleanse (kd, sizeof kd);
  OPENSSL_cleanse (sk, sizeof sk);
  OPENSSL_cleanse (z, sizeof z);
  OPENSSL_cleanse (m, sizeof m);
  OPENSSL_cleanse (mo, sizeof mo);
  BN_free (mx);
  BN_free (my);
  BN_clear_free (sx);
  BN_clear_free (sy);
  EC_POINT_free (qm);
  EC_POINT_free (s);
  return ok;
}

#pragma GCC diagnostic pop
