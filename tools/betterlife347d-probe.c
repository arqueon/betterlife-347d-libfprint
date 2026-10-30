/*
 * betterlife347d-probe — Safe read-only USB diagnostic tool for Blestech Betterlife
 * 347d:0302 (Match-On-Chip) and 347d:0304 (Match-On-Host) fingerprint sensors.
 *
 * Performs ONLY passive identification & session-handshake queries:
 *   0xA0 (Firmware Version), 0xA1 (Module Scheme), 0xA2 (SM2/SM3/SM4 Handshake),
 *   0xC0 (Module UID), 0xC1 (Sensor Info), and on MOC devices 0xB3 (Template Count).
 *
 * SAFETY INVARIANT: Never defines or sends 0xD0/0xD1/0xD2/0xC3.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <openssl/crypto.h>

#include "betterlife347d-proto.h"

#define BTL_VID    0x347d
#define BTL_EP_OUT 0x02
#define BTL_EP_IN  0x81

static int
count_frames (const uint8_t *buf, size_t got)
{
  size_t off = 0;
  int n = 0;

  while (off + 5 <= got)
    {
      if (buf[off] != 0xAA)
        break;
      uint32_t len = (uint32_t) buf[off + 1] |
                     ((uint32_t) buf[off + 2] << 8) |
                     ((uint32_t) buf[off + 3] << 16) |
                     ((uint32_t) buf[off + 4] << 24);
      size_t flen = (size_t) len + 5;
      if (len < 20 || off + flen > got)
        break;
      off += flen;
      n++;
    }
  return n;
}

static int
xfer_cmd (libusb_device_handle *h,
          uint8_t cmd, uint8_t sub,
          const uint8_t *data, size_t dlen,
          const uint8_t *key,
          uint8_t *rx, size_t rx_cap, size_t *rx_got_out)
{
  uint8_t tx[512];
  gssize n = btl_frame_build (tx, sizeof tx, cmd, sub, data, dlen, key, NULL);
  if (n < 0)
    return -1;

  int xfer = 0;
  int rc = libusb_bulk_transfer (h, BTL_EP_OUT, tx, (int) n, &xfer, 2000);
  if (rc != 0 || xfer != (int) n)
    {
      fprintf (stderr, "USB OUT cmd=0x%02x failed: %s\n", cmd, libusb_error_name (rc));
      return -1;
    }

  size_t got = 0;
  while (got < rx_cap)
    {
      xfer = 0;
      rc = libusb_bulk_transfer (h, BTL_EP_IN, rx + got, (int) (rx_cap - got), &xfer, 2500);
      if (xfer > 0)
        got += (size_t) xfer;
      if (rc == LIBUSB_ERROR_TIMEOUT)
        break;
      if (rc != 0)
        {
          fprintf (stderr, "USB IN cmd=0x%02x failed: %s\n", cmd, libusb_error_name (rc));
          return -1;
        }
      if (count_frames (rx, got) >= 1)
        break;
    }

  *rx_got_out = got;
  return count_frames (rx, got);
}

int
main (void)
{
  static const uint16_t pids[] = { 0x0302, 0x0304 };
  libusb_context *ctx = NULL;
  libusb_device_handle *h = NULL;
  uint16_t found_pid = 0;

  if (libusb_init (&ctx) != 0)
    {
      fprintf (stderr, "Failed to initialize libusb\n");
      return 1;
    }

  for (size_t i = 0; i < sizeof pids / sizeof pids[0]; i++)
    {
      h = libusb_open_device_with_vid_pid (ctx, BTL_VID, pids[i]);
      if (h)
        {
          found_pid = pids[i];
          break;
        }
    }

  if (!h)
    {
      fprintf (stderr, "No Betterlife 347d:0302 or 347d:0304 sensor found (or device busy / insufficient permissions).\n");
      libusb_exit (ctx);
      return 1;
    }

  libusb_set_auto_detach_kernel_driver (h, 1);
  int rc = libusb_claim_interface (h, 0);
  if (rc != 0)
    {
      fprintf (stderr, "Failed to claim USB interface 0 on 347d:%04x: %s (is fprintd holding it open?)\n",
               found_pid, libusb_error_name (rc));
      libusb_close (h);
      libusb_exit (ctx);
      return 1;
    }

  printf ("Betterlife USB Fingerprint Sensor detected: %04x:%04x\n", BTL_VID, found_pid);

  uint8_t rx[4096];
  for (int i = 0; i < 16; i++)
    {
      int xfer = 0;
      rc = libusb_bulk_transfer (h, BTL_EP_IN, rx, sizeof rx, &xfer, 80);
      if (rc == LIBUSB_ERROR_TIMEOUT && xfer == 0)
        break;
    }

  size_t got = 0;
  uint8_t rcmd = 0, rsub = 0;
  uint32_t rdlen = 0;
  const uint8_t *pl = NULL;

  /* 0xA0: Firmware Version */
  if (xfer_cmd (h, 0xA0, 0, NULL, 0, NULL, rx, sizeof rx, &got) >= 1 &&
      (pl = btl_frame_parse (rx, got, NULL, &rcmd, &rsub, &rdlen)) != NULL &&
      rdlen >= 7)
    {
      printf ("  Firmware     : mode=0x%02x (%s), project=0x%02x%02x, version=V%u.%u.%u.%u\n",
              pl[0], pl[0] == 0x01 ? "App" : "Boot/Other",
              pl[1], pl[2], pl[3], pl[4], pl[5], pl[6]);
    }

  /* 0xA1: Module Scheme */
  uint8_t scheme = 0xff;
  if (xfer_cmd (h, 0xA1, 0, NULL, 0, NULL, rx, sizeof rx, &got) >= 1 &&
      (pl = btl_frame_parse (rx, got, NULL, &rcmd, &rsub, &rdlen)) != NULL &&
      rdlen >= 4)
    {
      scheme = pl[0];
      const char *sname = (scheme == 0x10) ? "MOC (Match-On-Chip)"
                        : (scheme == 0x00) ? "MOH (Match-On-Host)"
                        : "Unknown";
      printf ("  Scheme       : 0x%02x (%s), crypto=[0x%02x, 0x%02x, 0x%02x] (SM2 + SM4-ECB + SM3)\n",
              pl[0], sname, pl[1], pl[2], pl[3]);
    }

  /* 0xA2: SM2 Ephemeral Session Handshake */
  BtlHandshake *hs = btl_handshake_new ();
  uint8_t pub[65];
  uint8_t sess[BTL_SESSKEY_LEN];
  int exit_code = 0;

  if (!hs || !btl_handshake_pubkey (hs, pub))
    {
      fprintf (stderr, "Failed to generate ephemeral SM2 keypair\n");
      exit_code = 1;
      goto out;
    }

  if (xfer_cmd (h, 0xA2, 0, pub, sizeof pub, NULL, rx, sizeof rx, &got) < 1 ||
      (pl = btl_frame_parse (rx, got, NULL, &rcmd, &rsub, &rdlen)) == NULL ||
      !btl_handshake_derive (hs, pl, rdlen, sess))
    {
      fprintf (stderr, "SM2/SM3/SM4 encrypted channel handshake failed\n");
      exit_code = 1;
      goto out;
    }
  printf ("  Secure Link  : ESTABLISHED (SM2 ECDH + SM3 MAC verified + SM4-ECB session key)\n");

  /* 0xC0: Module UID */
  if (xfer_cmd (h, 0xC0, 0, NULL, 0, sess, rx, sizeof rx, &got) >= 1 &&
      (pl = btl_frame_parse (rx, got, sess, &rcmd, &rsub, &rdlen)) != NULL &&
      rdlen > 0)
    {
      printf ("  Module UID   : ");
      for (uint32_t i = 0; i < rdlen; i++)
        printf ("%02x", pl[i]);
      printf (" (%u bytes)\n", rdlen);
    }

  /* 0xC1: Sensor Info */
  if (xfer_cmd (h, 0xC1, 0, NULL, 0, sess, rx, sizeof rx, &got) >= 1 &&
      (pl = btl_frame_parse (rx, got, sess, &rcmd, &rsub, &rdlen)) != NULL &&
      rdlen >= 8)
    {
      uint16_t chip = (uint16_t) pl[0] | ((uint16_t) pl[1] << 8);
      uint16_t w    = (uint16_t) pl[4] | ((uint16_t) pl[5] << 8);
      uint16_t hpx  = (uint16_t) pl[6] | ((uint16_t) pl[7] << 8);
      printf ("  Sensor Chip  : 0x%04x (%ux%u px)\n", chip, w, hpx);
    }

  /* 0xB3: On-Chip Enrolled Template Count (MOC only) */
  if (scheme == 0x10 &&
      xfer_cmd (h, 0xB3, 0, NULL, 0, sess, rx, sizeof rx, &got) >= 1 &&
      (pl = btl_frame_parse (rx, got, sess, &rcmd, &rsub, &rdlen)) != NULL &&
      rdlen >= 4)
    {
      uint16_t used = (uint16_t) pl[0] | ((uint16_t) pl[1] << 8);
      uint16_t cap  = (uint16_t) pl[2] | ((uint16_t) pl[3] << 8);
      printf ("  MCU Storage  : %u / %u fingerprint slots used\n", used, cap);
    }

out:
  OPENSSL_cleanse (sess, sizeof sess);
  btl_handshake_free (hs);
  libusb_release_interface (h, 0);
  libusb_close (h);
  libusb_exit (ctx);
  return exit_code;
}
