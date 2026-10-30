/*
 * Blestech / Shenzhen Betterlife 347d:0302 Match-On-Chip (MOC) driver for libfprint-2
 *
 * Native FpDevice driver for the Betterlife 347d:0302 USB fingerprint reader
 * ("btlfp Betterlife Fingerprint", chip ID 0x5f83, 112x96 sensor, 10 on-chip
 * template slots). Uses an SM2 ECDH + SM3 KDF/MAC + SM4-ECB per-frame nonce
 * encrypted channel over Bulk EP 0x02 OUT / EP 0x81 IN; see betterlife347d-proto.c.
 *
 * SAFETY INVARIANT:
 *   Firmware-restore, firmware-update, bootloader mode-switch, and JTAG control
 *   commands (0xD0, 0xD1, 0xD2, 0xC3) are NEVER defined or transmitted.
 *
 * Copyright (C) 2026 Rubén García Sánchez & contributors
 * Protocol framing & SM2/SM3/SM4 helpers: Copyright (C) 2026 huellero project
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "betterlife347d_moc"
#include "fpi-log.h"

#include "drivers_api.h"
#include "betterlife347d-proto.h"

#include <openssl/crypto.h>
#include <string.h>

#define BTL_EP_OUT (0x02 | FPI_USB_ENDPOINT_OUT)
#define BTL_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)

/* Full-Speed USB bulk wMaxPacketSize is 64 bytes; always submit 64*N IN URBs */
#define BTL_BULK_IN_CHUNK           512

#define BTL_WRITE_TIMEOUT_MS        1500
#define BTL_WRITE_MAX_RETRIES       2

#define BTL_SYNC_ATTEMPT_MS         1500
#define BTL_SYNC_MAX_ATTEMPTS       3

/* Matches BetterlifeFingerprintDevice.dll 0xB0/2: 2000 ms per wait, 8000 ms total */
#define BTL_COMMIT_ATTEMPT_MS       2000
#define BTL_COMMIT_MAX_ATTEMPTS     4

#define BTL_CANCEL_TIMEOUT_MS       1000
#define BTL_DRAIN_TIMEOUT_MS        60
#define BTL_DRAIN_MAX_READS         16
#define BTL_HS_MAX_RETRIES          4
#define BTL_INTER_CAPTURE_DELAY_MS  450

#define BTL_DEFAULT_STAGES          7
#define BTL_FUID_LEN                16
#define BTL_TAG_LEN                 32
#define BTL_TX_CAP                  512
#define BTL_RX_CAP                  4096
#define BTL_REPLY_CAP               512
#define BTL_MAX_FRAME_LEN           1024

/* Safe operational command set only (NEVER 0xD0/0xD1/0xD2/0xC3). */
#define BTL_CMD_FW_VER              0xA0
#define BTL_CMD_SCHEME              0xA1
#define BTL_CMD_HANDSHAKE           0xA2
#define BTL_CMD_ENROLL              0xB0
#define BTL_CMD_IDENTIFY            0xB1
#define BTL_CMD_DELETE              0xB2
#define BTL_CMD_QUERY_COUNT         0xB3
#define BTL_CMD_MODULE_UID          0xC0
#define BTL_CMD_SENSOR_INFO         0xC1

#define BTL_SUB_ANY                 0xFF
#define BTL_SCHEME_MOC              0x10

/* Official Betterlife MOC MCU wire status codes (BetterlifeSensorAdapter.dll) */
#define BTL_STATUS_OK               0x00 /* [All scene] No Error */
#define BTL_STATUS_LEGACY_NO_MATCH  0x0B /* Legacy WinBio internal no-match */
#define BTL_STATUS_NO_FINGER        0x10 /* [Enroll] No finger press (wait timeout) */
#define BTL_STATUS_LIFT_TOO_FAST    0x11 /* [Enroll] Fingers lift too fast */
#define BTL_STATUS_DUPLICATE        0x12 /* [Enroll] Current input finger already registered */
#define BTL_STATUS_SAVE_FAIL        0x13 /* [Enroll] Template saving failed */
#define BTL_STATUS_OVERLAP          0x14 /* [Enroll] Overlap rate of entry area too large */
#define BTL_STATUS_DB_EMPTY         0x20 /* [Identify] Fingerprint entry quantity is 0 */
#define BTL_STATUS_NO_MATCH         0x21 /* [Identify] No matching template */
#define BTL_STATUS_FINGER_AWAY      0x30 /* [Enroll/Identify] Finger away */
#define BTL_STATUS_ALGO_FAIL        0x31 /* [Enroll/Identify] Algorithm processing failed */
#define BTL_STATUS_NONLIVING        0x32 /* [Enroll/Identify] Nonliving body */
#define BTL_STATUS_TOO_WET          0x33 /* [Enroll/Identify] Fingerprint is too wet */
#define BTL_STATUS_TOO_DRY          0x34 /* [Enroll/Identify] Fingerprint is too dry */
#define BTL_STATUS_AREA_SMALL       0x35 /* [Enroll/Identify] Valid area is too small */
#define BTL_STATUS_POOR_QUALITY     0x36 /* [Enroll/Identify] Fingerprint quality is too poor */
#define BTL_STATUS_PARTIAL_TOUCH    0x37 /* [Enroll/Identify] Partial/off-center touch (347d:0302 V1.0.0.0) */
#define BTL_STATUS_ID_NOT_EXIST     0x40 /* [Remove] Non-existent fingerprint ID */
#define BTL_STATUS_FLASH_ERR        0x41 /* [E/I/R] Flash read/write information failed */
#define BTL_STATUS_UNSUPPORTED      0x80 /* [Universal] Unsupported directive */
#define BTL_STATUS_UNDEFINED        0x81 /* [Universal] Undefined error */
#define BTL_STATUS_INTERIOR_ERR     0xF0 /* [Interior] Reply received with interior error */

enum init_states {
  INIT_DRAIN,
  INIT_A0_SEND,
  INIT_A0_READ,
  INIT_A0_PARSE,
  INIT_A1_SEND,
  INIT_A1_READ,
  INIT_A1_PARSE,
  INIT_A2_SEND,
  INIT_A2_READ,
  INIT_DERIVE,
  INIT_C0_SEND,
  INIT_C0_READ,
  INIT_C0_PARSE,
  INIT_C1_SEND,
  INIT_C1_READ,
  INIT_C1_PARSE,
  INIT_B3_SEND,
  INIT_B3_READ,
  INIT_B3_PARSE,
  INIT_NUM_STATES,
};

enum enroll_states {
  ENROLL_PRE_CANCEL_MATCH,
  ENROLL_PRE_CANCEL_ENROLL,
  ENROLL_PRE_DRAIN,
  ENROLL_COUNT_SEND,
  ENROLL_COUNT_READ,
  ENROLL_COUNT_PARSE,
  ENROLL_START_SEND,
  ENROLL_START_READ,
  ENROLL_START_PARSE,
  ENROLL_STEP_SETTLE,
  ENROLL_STEP_SEND,
  ENROLL_STEP_WAIT,
  ENROLL_STEP_PARSE,
  ENROLL_COMMIT_SETTLE,
  ENROLL_COMMIT_SEND,
  ENROLL_COMMIT_READ,
  ENROLL_COMMIT_PARSE,
  ENROLL_CANCEL_SEND,
  ENROLL_CANCEL_READ,
  ENROLL_CANCEL_DRAIN,
  ENROLL_CANCEL_DONE,
  ENROLL_NUM_STATES,
};

enum match_states {
  MATCH_PRE_CANCEL_ENROLL,
  MATCH_PRE_CANCEL_MATCH,
  MATCH_PRE_DRAIN,
  MATCH_SETTLE,
  MATCH_START_SEND,
  MATCH_WAIT,
  MATCH_PARSE,
  MATCH_CANCEL_SEND,
  MATCH_CANCEL_READ,
  MATCH_CANCEL_DRAIN,
  MATCH_CANCEL_DONE,
  MATCH_NUM_STATES,
};

enum del_states {
  DEL_PRE_CANCEL_ENROLL,
  DEL_PRE_CANCEL_MATCH,
  DEL_PRE_DRAIN,
  DEL_SEND,
  DEL_READ,
  DEL_PARSE,
  DEL_NUM_STATES,
};

struct _FpiDeviceBetterlife347dMoc
{
  FpDevice      parent;

  FpiSsm       *ssm;
  BtlHandshake *hs;
  guint8        sess[BTL_SESSKEY_LEN];
  gboolean      have_session;
  gboolean      is_probe;
  gboolean      mcu_enrolling;
  gboolean      mcu_matching;

  guint8        pub[65];
  gint          hs_retries;
  gint          drain_left;

  gchar        *module_uid_hex;
  guint16       chip_id;
  guint16       sensor_w;
  guint16       sensor_h;
  guint16       enrolled_count;
  guint16       max_capacity;

  gint          total_stages;
  gint          enroll_stage;      /* 1-based stage sent to 0xB0/1; increments ONLY on pl[0]==0 */
  gint          completed_stages;
  guint8        enroll_tag[BTL_TAG_LEN];
  guint8        del_tag[BTL_TAG_LEN];

  GError       *cancel_error;
  gint          cancel_state;
  gint64        last_capture_us;

  /* Synchronous TX/RX retry state (mirrors BetterlifeFingerprintDevice.dll) */
  gint          active_send_state;
  gint          cmd_attempt;
  gint          write_retries;
  gsize         tx_len;
  guint8        tx_cmd;
  guint8        tx_sub;
  guint         tx_timeout_ms;

  guint8        tx[BTL_TX_CAP];
  guint8        rx[BTL_RX_CAP];
  gsize         rx_got;

  guint8        expect_cmd;
  guint8        expect_sub;
  guint32       min_dlen;
  gboolean      rx_encrypted;
  guint         rx_timeout_ms;
  gint          retry_send_state;
  gint          retry_max_attempts;
  GCancellable *rx_cancellable;    /* unowned borrow during read loop */

  gboolean      have_reply;
  guint8        reply_cmd;
  guint8        reply_sub;
  guint32       reply_len;
  guint8        reply_buf[BTL_REPLY_CAP];
};

G_DECLARE_FINAL_TYPE (FpiDeviceBetterlife347dMoc, fpi_device_betterlife347d_moc,
                      FPI, DEVICE_BETTERLIFE347D_MOC, FpDevice);
G_DEFINE_TYPE (FpiDeviceBetterlife347dMoc, fpi_device_betterlife347d_moc, FP_TYPE_DEVICE);

/* ---- Helpers, framing, single-decrypt stream parser & retry engine ------- */

static gboolean
btl_moc_is_emulated (void)
{
  return g_strcmp0 (g_getenv ("FP_DEVICE_EMULATION"), "1") == 0;
}

static gint
btl_moc_settle_delay_ms (FpiDeviceBetterlife347dMoc *self)
{
  gint64 elapsed_ms;

  if (self->last_capture_us <= 0 || btl_moc_is_emulated ())
    return 0;

  elapsed_ms = (g_get_monotonic_time () - self->last_capture_us) / 1000;
  if (elapsed_ms >= BTL_INTER_CAPTURE_DELAY_MS)
    return 0;

  return (gint) (BTL_INTER_CAPTURE_DELAY_MS - elapsed_ms);
}

static GError *
btl_moc_retry_error (guint8 status)
{
  switch (status)
    {
    case BTL_STATUS_LIFT_TOO_FAST:
    case BTL_STATUS_FINGER_AWAY:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);

    case BTL_STATUS_OVERLAP:
    case BTL_STATUS_AREA_SMALL:
    case BTL_STATUS_PARTIAL_TOUCH:
      return fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);

    case BTL_STATUS_TOO_WET:
      return fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);

    case BTL_STATUS_ALGO_FAIL:
    case BTL_STATUS_NONLIVING:
    case BTL_STATUS_TOO_DRY:
    case BTL_STATUS_POOR_QUALITY:
    default:
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    }
}

static void
btl_moc_populate_print (FpPrint      *print,
                        const guint8  fuid[BTL_FUID_LEN],
                        const gchar  *tag_desc)
{
  GVariant *fuid_var;
  GVariant *fpi_data;

  fuid_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, fuid, BTL_FUID_LEN, 1);
  fpi_data = g_variant_new ("(@ay)", fuid_var);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", fpi_data, NULL);
  if (tag_desc && tag_desc[0] != '\0')
    fp_print_set_description (print, tag_desc);
}

/*
 * Scans self->rx for complete 0xAA frames, decrypting each complete frame
 * ONCE in a scratch buffer (btl_frame_parse mutates ciphertext in place) and
 * consuming it from self->rx. Skips empty dlen==0 ACK frames and stale frames
 * until a frame matching (expect_cmd, expect_sub, rdlen >= min_dlen) arrives.
 */
static gboolean
btl_moc_try_extract_reply (FpiDeviceBetterlife347dMoc *self)
{
  guint8 scratch[BTL_MAX_FRAME_LEN + 8];
  const guint8 *key = self->rx_encrypted ? self->sess : NULL;

  while (self->rx_got > 0)
    {
      guint32 len;
      gsize flen;
      guint8 rcmd = 0, rsub = 0;
      guint32 rdlen = 0;
      const guint8 *pl;

      if (self->rx[0] != 0xAA)
        {
          const guint8 *p = memchr (self->rx, 0xAA, self->rx_got);
          if (!p)
            {
              self->rx_got = 0;
              return FALSE;
            }
          gsize skip = (gsize) (p - self->rx);
          self->rx_got -= skip;
          memmove (self->rx, p, self->rx_got);
        }

      if (self->rx_got < 5)
        return FALSE;

      len = (guint32) self->rx[1] |
            ((guint32) self->rx[2] << 8) |
            ((guint32) self->rx[3] << 16) |
            ((guint32) self->rx[4] << 24);

      if (len < 20 || len > BTL_MAX_FRAME_LEN)
        {
          /* Invalid header length; advance one byte to resync on next 0xAA */
          self->rx_got--;
          if (self->rx_got > 0)
            memmove (self->rx, self->rx + 1, self->rx_got);
          continue;
        }

      flen = (gsize) len + 5;
      if (self->rx_got < flen)
        return FALSE;

      memcpy (scratch, self->rx, flen);
      self->rx_got -= flen;
      if (self->rx_got > 0)
        memmove (self->rx, self->rx + flen, self->rx_got);

      pl = btl_frame_parse (scratch, flen, key, &rcmd, &rsub, &rdlen);
      if (!pl)
        {
          OPENSSL_cleanse (scratch, flen);
          fp_warn ("Ignoring invalid/stale RX frame (flen=%zu, expect=0x%02x/%u)",
                   flen, self->expect_cmd, self->expect_sub);
          continue;
        }

      if (rcmd == self->expect_cmd &&
          (self->expect_sub == BTL_SUB_ANY || rsub == self->expect_sub))
        {
          if (rdlen < self->min_dlen)
            {
              /*
               * Normal immediate ACK frame preceding an async capture/commit result
               * (e.g. dlen==0 on 0xB1/0 or dlen==1 echoing stage_byte on 0xB0/1).
               */
              OPENSSL_cleanse (scratch, flen);
              fp_dbg ("Received ACK frame for 0x%02x/%u (dlen=%u, waiting for >=%u)",
                      rcmd, rsub, rdlen, self->min_dlen);
              continue;
            }

          self->have_reply = TRUE;
          self->reply_cmd = rcmd;
          self->reply_sub = rsub;
          self->reply_len = MIN (rdlen, (guint32) sizeof self->reply_buf);
          if (self->reply_len > 0)
            memcpy (self->reply_buf, pl, self->reply_len);
          OPENSSL_cleanse (scratch, flen);
          return TRUE;
        }

      OPENSSL_cleanse (scratch, flen);
      fp_warn ("Discarding stale RX frame cmd=0x%02x/%u dlen=%u (wanted 0x%02x/%u)",
               rcmd, rsub, rdlen, self->expect_cmd, self->expect_sub);
    }

  return FALSE;
}

static void btl_moc_send_submit (FpiDeviceBetterlife347dMoc *self, FpiSsm *ssm);

static void
btl_moc_send_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  if (error)
    {
      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
          self->write_retries < BTL_WRITE_MAX_RETRIES)
        {
          self->write_retries++;
          fp_warn ("Bulk OUT timeout on cmd=0x%02x/%u, retry %d/%d",
                   self->tx_cmd, self->tx_sub, self->write_retries, BTL_WRITE_MAX_RETRIES);
          g_error_free (error);
          btl_moc_send_submit (self, transfer->ssm);
          return;
        }

      fp_warn ("Bulk OUT failed on cmd=0x%02x/%u state=%d: %s",
               self->tx_cmd, self->tx_sub,
               fpi_ssm_get_cur_state (transfer->ssm),
               error->message);
      self->active_send_state = -1;
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

static void
btl_moc_send_submit (FpiDeviceBetterlife347dMoc *self, FpiSsm *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, BTL_EP_OUT, self->tx, self->tx_len, NULL);
  fpi_usb_transfer_submit (t, self->tx_timeout_ms, NULL, btl_moc_send_cb, NULL);
}

static void
btl_moc_send (FpiDeviceBetterlife347dMoc *self,
              FpiSsm                     *ssm,
              guint8                      cmd,
              guint8                      sub,
              const guint8               *data,
              gsize                       dlen,
              const guint8               *key,
              guint                       timeout_ms)
{
  gint cur_state = fpi_ssm_get_cur_state (ssm);
  gssize n = btl_frame_build (self->tx, sizeof self->tx, cmd, sub, data, dlen, key, NULL);

  if (n < 0)
    {
      self->active_send_state = -1;
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  if (self->active_send_state != cur_state)
    {
      self->active_send_state = cur_state;
      self->cmd_attempt = 0;
    }

  self->write_retries = 0;
  self->tx_len = (gsize) n;
  self->tx_cmd = cmd;
  self->tx_sub = sub;
  self->tx_timeout_ms = timeout_ms;
  /* Clear RX accumulator before a fresh command transmission */
  self->rx_got = 0;
  self->have_reply = FALSE;

  btl_moc_send_submit (self, ssm);
}

/* Best-effort cancel write: ignores USB errors so cleanup never masks root error */
static void
btl_moc_best_effort_cb (FpiUsbTransfer *transfer,
                        FpDevice       *dev,
                        gpointer        user_data,
                        GError         *error)
{
  g_clear_error (&error);
  fpi_ssm_next_state (transfer->ssm);
}

static void
btl_moc_send_best_effort (FpiDeviceBetterlife347dMoc *self,
                          FpiSsm                     *ssm,
                          guint8                      cmd,
                          guint8                      sub,
                          const guint8               *data,
                          gsize                       dlen)
{
  FpiUsbTransfer *t;
  gssize n;

  if (!self->have_session)
    {
      fpi_ssm_next_state (ssm);
      return;
    }

  n = btl_frame_build (self->tx, sizeof self->tx, cmd, sub, data, dlen, self->sess, NULL);
  if (n < 0)
    {
      fpi_ssm_next_state (ssm);
      return;
    }

  t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (t, BTL_EP_OUT, self->tx, (gsize) n, NULL);
  fpi_usb_transfer_submit (t, BTL_CANCEL_TIMEOUT_MS, NULL, btl_moc_best_effort_cb, NULL);
}

static void btl_moc_read_submit (FpiDeviceBetterlife347dMoc *self, FpiSsm *ssm);

static void
btl_moc_read_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  if (transfer->actual_length > 0)
    {
      if (self->rx_got + (gsize) transfer->actual_length > sizeof self->rx)
        self->rx_got = 0;

      memcpy (self->rx + self->rx_got, transfer->buffer, (gsize) transfer->actual_length);
      self->rx_got += (gsize) transfer->actual_length;

      if (btl_moc_try_extract_reply (self))
        {
          g_clear_error (&error);
          self->cancel_state = -1;
          self->active_send_state = -1;
          fpi_ssm_next_state (transfer->ssm);
          return;
        }
    }

  if (error)
    {
      if (self->cancel_state >= 0 &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_clear_error (&self->cancel_error);
          self->cancel_error = error;
          gint jump = self->cancel_state;
          self->cancel_state = -1;
          self->active_send_state = -1;
          fpi_ssm_jump_to_state (transfer->ssm, jump);
          return;
        }

      if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) &&
          self->retry_send_state >= 0 &&
          ++self->cmd_attempt < self->retry_max_attempts)
        {
          fp_warn ("RX timeout waiting for 0x%02x/%u (attempt %d/%d), retransmitting",
                   self->expect_cmd, self->expect_sub,
                   self->cmd_attempt, self->retry_max_attempts);
          g_error_free (error);
          fpi_ssm_jump_to_state (transfer->ssm, self->retry_send_state);
          return;
        }

      fp_warn ("Bulk IN failed waiting for 0x%02x/%u state=%d: %s",
               self->expect_cmd, self->expect_sub,
               fpi_ssm_get_cur_state (transfer->ssm),
               error->message);
      self->cancel_state = -1;
      self->active_send_state = -1;
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  btl_moc_read_submit (self, transfer->ssm);
}

static void
btl_moc_read_submit (FpiDeviceBetterlife347dMoc *self, FpiSsm *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  /* Always submit a multiple of 64-byte Full-Speed wMaxPacketSize */
  fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, BTL_BULK_IN_CHUNK);
  fpi_usb_transfer_submit (t, self->rx_timeout_ms, self->rx_cancellable,
                           btl_moc_read_cb, NULL);
}

static void
btl_moc_read_start (FpiDeviceBetterlife347dMoc *self,
                    FpiSsm                     *ssm,
                    guint8                      expect_cmd,
                    guint8                      expect_sub,
                    guint32                     min_dlen,
                    gboolean                    encrypted,
                    guint                       timeout_ms,
                    gint                        retry_send_state,
                    gint                        retry_max_attempts,
                    GCancellable               *cancellable,
                    gint                        cancel_jump_state)
{
  self->expect_cmd = expect_cmd;
  self->expect_sub = expect_sub;
  self->min_dlen = min_dlen;
  self->rx_encrypted = encrypted;
  self->rx_timeout_ms = timeout_ms;
  self->retry_send_state = retry_send_state;
  self->retry_max_attempts = retry_max_attempts;
  self->rx_cancellable = cancellable;
  self->cancel_state = cancel_jump_state;
  self->have_reply = FALSE;

  if (self->rx_got > 0 && btl_moc_try_extract_reply (self))
    {
      self->cancel_state = -1;
      self->active_send_state = -1;
      fpi_ssm_next_state (ssm);
      return;
    }

  btl_moc_read_submit (self, ssm);
}

/* Fast drain helper: flushes stale IN packets and stops immediately once
 * EP 0x81 IN times out with 0 bytes so open/cancel stays <100 ms. */
static void
btl_moc_drain_cb (FpiUsbTransfer *transfer,
                  FpDevice       *dev,
                  gpointer        user_data,
                  GError         *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  gboolean timed_out = error &&
                       g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);

  g_clear_error (&error);

  if ((timed_out && transfer->actual_length <= 0) || --self->drain_left <= 0)
    {
      self->rx_got = 0;
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  t->ssm = transfer->ssm;
  fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, BTL_BULK_IN_CHUNK);
  fpi_usb_transfer_submit (t, BTL_DRAIN_TIMEOUT_MS, NULL, btl_moc_drain_cb, NULL);
}

static void
btl_moc_drain_start (FpiDeviceBetterlife347dMoc *self, FpiSsm *ssm, gint max_reads)
{
  FpiUsbTransfer *t;

  self->rx_got = 0;
  if (btl_moc_is_emulated ())
    {
      fpi_ssm_next_state (ssm);
      return;
    }

  t = fpi_usb_transfer_new (FP_DEVICE (self));
  self->drain_left = max_reads;
  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, BTL_BULK_IN_CHUNK);
  fpi_usb_transfer_submit (t, BTL_DRAIN_TIMEOUT_MS, NULL, btl_moc_drain_cb, NULL);
}

/* ---- Session initialization (shared by probe & open) --------------------- */

static void
btl_moc_init_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  const guint8 *pl = self->reply_buf;
  guint32 rdlen = self->reply_len;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case INIT_DRAIN:
      btl_moc_drain_start (self, ssm, BTL_DRAIN_MAX_READS);
      break;

    case INIT_A0_SEND:
      btl_moc_send (self, ssm, BTL_CMD_FW_VER, 0, NULL, 0, NULL, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_A0_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_FW_VER, BTL_SUB_ANY, 1, FALSE,
                          BTL_SYNC_ATTEMPT_MS, INIT_A0_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case INIT_A0_PARSE:
      if (!self->have_reply || rdlen < 1 || pl[0] != 0x01)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Unexpected 0xA0 firmware state"));
          break;
        }
      if (rdlen >= 7)
        fp_dbg ("Betterlife 347d:0302 fw proj=0x%02x%02x V%u.%u.%u.%u",
                pl[1], pl[2], pl[3], pl[4], pl[5], pl[6]);
      fpi_ssm_next_state (ssm);
      break;

    case INIT_A1_SEND:
      btl_moc_send (self, ssm, BTL_CMD_SCHEME, 0, NULL, 0, NULL, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_A1_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_SCHEME, BTL_SUB_ANY, 4, FALSE,
                          BTL_SYNC_ATTEMPT_MS, INIT_A1_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case INIT_A1_PARSE:
      if (!self->have_reply || rdlen < 4)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      if (pl[0] != BTL_SCHEME_MOC)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                         "Unsupported module scheme 0x%02x (expected MOC 0x10)",
                                                         pl[0]));
          break;
        }
      fpi_ssm_next_state (ssm);
      break;

    case INIT_A2_SEND:
      g_clear_pointer (&self->hs, btl_handshake_free);
      self->hs = btl_handshake_new ();
      if (!self->hs || !btl_handshake_pubkey (self->hs, self->pub))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          break;
        }
      btl_moc_send (self, ssm, BTL_CMD_HANDSHAKE, 0, self->pub, sizeof self->pub,
                    NULL, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_A2_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_HANDSHAKE, BTL_SUB_ANY, 112, FALSE,
                          BTL_SYNC_ATTEMPT_MS, -1, 0, NULL, -1);
      break;

    case INIT_DERIVE:
      if (self->have_reply && rdlen >= 112 &&
          btl_handshake_derive (self->hs, pl, rdlen, self->sess))
        {
          g_clear_pointer (&self->hs, btl_handshake_free);
          self->have_session = TRUE;
          fpi_ssm_next_state (ssm);
          break;
        }

      g_clear_pointer (&self->hs, btl_handshake_free);
      if (self->hs_retries++ < BTL_HS_MAX_RETRIES)
        {
          fp_dbg ("SM2/SM4 handshake retry %d/%d", self->hs_retries, BTL_HS_MAX_RETRIES);
          fpi_ssm_jump_to_state (ssm, INIT_DRAIN);
          break;
        }
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      break;

    case INIT_C0_SEND:
      btl_moc_send (self, ssm, BTL_CMD_MODULE_UID, 0, NULL, 0,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_C0_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_MODULE_UID, BTL_SUB_ANY, 1, TRUE,
                          BTL_SYNC_ATTEMPT_MS, INIT_C0_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case INIT_C0_PARSE:
      if (!self->have_reply || rdlen == 0 || rdlen > 64)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      else
        {
          GString *hex = g_string_sized_new (rdlen * 2 + 1);
          for (guint32 i = 0; i < rdlen; i++)
            g_string_append_printf (hex, "%02x", pl[i]);
          g_free (self->module_uid_hex);
          self->module_uid_hex = g_string_free (hex, FALSE);
        }
      fpi_ssm_next_state (ssm);
      break;

    case INIT_C1_SEND:
      btl_moc_send (self, ssm, BTL_CMD_SENSOR_INFO, 0, NULL, 0,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_C1_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_SENSOR_INFO, BTL_SUB_ANY, 8, TRUE,
                          BTL_SYNC_ATTEMPT_MS, INIT_C1_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case INIT_C1_PARSE:
      if (self->have_reply && rdlen >= 8)
        {
          self->chip_id  = (guint16) pl[0] | ((guint16) pl[1] << 8);
          self->sensor_w = (guint16) pl[4] | ((guint16) pl[5] << 8);
          self->sensor_h = (guint16) pl[6] | ((guint16) pl[7] << 8);
          fp_dbg ("Betterlife sensor chip=0x%04x %ux%u",
                  self->chip_id, self->sensor_w, self->sensor_h);
        }
      fpi_ssm_next_state (ssm);
      break;

    case INIT_B3_SEND:
      btl_moc_send (self, ssm, BTL_CMD_QUERY_COUNT, 0, NULL, 0,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case INIT_B3_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_QUERY_COUNT, BTL_SUB_ANY, 4, TRUE,
                          BTL_SYNC_ATTEMPT_MS, INIT_B3_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case INIT_B3_PARSE:
      if (!self->have_reply || rdlen < 4)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      self->enrolled_count = (guint16) pl[0] | ((guint16) pl[1] << 8);
      self->max_capacity   = (guint16) pl[2] | ((guint16) pl[3] << 8);
      fp_dbg ("Betterlife MOC storage: %u / %u slots used",
              self->enrolled_count, self->max_capacity);
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
btl_moc_init_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);

  self->ssm = NULL;
  self->active_send_state = -1;
  g_clear_pointer (&self->hs, btl_handshake_free);

  if (self->is_probe)
    {
      OPENSSL_cleanse (self->sess, sizeof self->sess);
      self->have_session = FALSE;
      g_usb_device_release_interface (usb_dev, 0, 0, NULL);
      g_usb_device_close (usb_dev, NULL);

      if (error)
        {
          fpi_device_probe_complete (dev, NULL, NULL, error);
          return;
        }

      if (btl_moc_is_emulated ())
        fpi_device_probe_complete (dev, "emulated-betterlife347d-moc", NULL, NULL);
      else
        fpi_device_probe_complete (dev, self->module_uid_hex, NULL, NULL);
      return;
    }

  if (error)
    {
      OPENSSL_cleanse (self->sess, sizeof self->sess);
      self->have_session = FALSE;
      g_usb_device_release_interface (usb_dev, 0, 0, NULL);
      g_usb_device_close (usb_dev, NULL);
    }

  fpi_device_open_complete (dev, error);
}

static void
btl_moc_probe (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  GError *error = NULL;

  if (!g_usb_device_open (usb_dev, &error))
    {
      fpi_device_probe_complete (dev, NULL, NULL, error);
      return;
    }

  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      g_usb_device_close (usb_dev, NULL);
      fpi_device_probe_complete (dev, NULL, NULL, error);
      return;
    }

  self->is_probe = TRUE;
  self->have_session = FALSE;
  self->mcu_enrolling = FALSE;
  self->mcu_matching = FALSE;
  self->hs_retries = 0;
  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_init_ssm, INIT_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_init_complete);
}

static void
btl_moc_open (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  GError *error = NULL;

  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      g_usb_device_close (usb_dev, NULL);
      fpi_device_open_complete (dev, error);
      return;
    }

  self->is_probe = FALSE;
  self->have_session = FALSE;
  self->mcu_enrolling = FALSE;
  self->mcu_matching = FALSE;
  self->hs_retries = 0;
  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_init_ssm, INIT_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_init_complete);
}

static void
btl_moc_close (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  GError *error = NULL;

  OPENSSL_cleanse (self->sess, sizeof self->sess);
  self->have_session = FALSE;
  self->mcu_enrolling = FALSE;
  self->mcu_matching = FALSE;
  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);
  fpi_device_close_complete (dev, error);
}

/* ---- Enrollment (0xB3 -> 0xB0/0 -> 0xB0/1 loop -> 0xB0/2 commit) --------- */

static void
btl_moc_prepare_enroll_tag (FpiDeviceBetterlife347dMoc *self, FpPrint *print)
{
  g_autofree gchar *uid = fpi_print_generate_user_id (print);
  gsize len;

  memset (self->enroll_tag, 0, sizeof self->enroll_tag);
  if (uid && uid[0] != '\0')
    {
      len = MIN (strlen (uid), BTL_TAG_LEN - 1);
      memcpy (self->enroll_tag, uid, len);
    }
  else
    {
      g_snprintf ((gchar *) self->enroll_tag, BTL_TAG_LEN,
                  "FP1-BTL-%08x%08x",
                  (guint) g_random_int (), (guint) g_random_int ());
    }
}

static void
btl_moc_enroll_fail_cleanup (FpiDeviceBetterlife347dMoc *self,
                             FpiSsm                     *ssm,
                             GError                     *err)
{
  if (self->mcu_enrolling)
    {
      g_clear_error (&self->cancel_error);
      self->cancel_error = err;
      fpi_ssm_jump_to_state (ssm, ENROLL_CANCEL_SEND);
    }
  else
    {
      fpi_ssm_mark_failed (ssm, err);
    }
}

static void
btl_moc_enroll_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  const guint8 *pl = self->reply_buf;
  guint32 rdlen = self->reply_len;
  static const guint8 zero1 = 0x00;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_PRE_CANCEL_MATCH:
      if (self->mcu_matching)
        {
          self->mcu_matching = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_IDENTIFY, 1, NULL, 0);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case ENROLL_PRE_CANCEL_ENROLL:
      if (self->mcu_enrolling)
        {
          self->mcu_enrolling = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_ENROLL, 3, &zero1, 1);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case ENROLL_PRE_DRAIN:
      btl_moc_drain_start (self, ssm, 8);
      break;

    case ENROLL_COUNT_SEND:
      btl_moc_send (self, ssm, BTL_CMD_QUERY_COUNT, 0, NULL, 0,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case ENROLL_COUNT_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_QUERY_COUNT, BTL_SUB_ANY, 4, TRUE,
                          BTL_SYNC_ATTEMPT_MS, ENROLL_COUNT_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case ENROLL_COUNT_PARSE:
      if (!self->have_reply || rdlen < 4)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      self->enrolled_count = (guint16) pl[0] | ((guint16) pl[1] << 8);
      self->max_capacity   = (guint16) pl[2] | ((guint16) pl[3] << 8);
      fp_dbg ("0xB3 slots=%u/%u", self->enrolled_count, self->max_capacity);
      if (self->max_capacity > 0 && self->enrolled_count >= self->max_capacity)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_FULL));
          break;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_START_SEND:
      btl_moc_send (self, ssm, BTL_CMD_ENROLL, 0, &zero1, 1,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case ENROLL_START_READ:
      /* BetterlifeFingerprintDevice.dll 0x180015ffa: 0xB0/0 reply is 2 bytes {status, max_stages} */
      btl_moc_read_start (self, ssm, BTL_CMD_ENROLL, 0, 2, TRUE,
                          BTL_SYNC_ATTEMPT_MS, ENROLL_START_SEND, BTL_SYNC_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case ENROLL_START_PARSE:
      if (!self->have_reply || rdlen < 2)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      if (pl[0] != BTL_STATUS_OK)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                         "MCU rejected enroll start (status 0x%02x)",
                                                         pl[0]));
          break;
        }
      self->mcu_enrolling = TRUE;
      self->total_stages = (rdlen >= 2 && pl[1] > 0) ? (gint) pl[1] : BTL_DEFAULT_STAGES;
      fp_dbg ("0xB0/0 enroll started (max_stages=%d)", self->total_stages);
      if (fp_device_get_nr_enroll_stages (dev) != self->total_stages)
        fpi_device_set_nr_enroll_stages (dev, self->total_stages);

      self->enroll_stage = 1;
      self->completed_stages = 0;
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_PRESENT);
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_STEP_SETTLE:
      {
        gint wait_ms;

        if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
          {
            fpi_ssm_jump_to_state (ssm, ENROLL_CANCEL_SEND);
            break;
          }

        wait_ms = btl_moc_settle_delay_ms (self);
        if (wait_ms > 0)
          fpi_ssm_next_state_delayed (ssm, wait_ms);
        else
          fpi_ssm_next_state (ssm);
        break;
      }

    case ENROLL_STEP_SEND:
      {
        guint8 stage_byte = (guint8) self->enroll_stage;

        if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
          {
            fpi_ssm_jump_to_state (ssm, ENROLL_CANCEL_SEND);
            break;
          }

        btl_moc_send (self, ssm, BTL_CMD_ENROLL, 1, &stage_byte, 1,
                      self->sess, BTL_WRITE_TIMEOUT_MS);
        break;
      }

    case ENROLL_STEP_WAIT:
      /*
       * BetterlifeFingerprintDevice.dll 0x180016067: 0xB0/1 emits an immediate
       * ACK frame (dlen==1 echoing stage_byte on 347d:0302 V1.0.0.0, or dlen==0)
       * followed after finger contact by a 2-byte result frame {status, cur}.
       * Requiring min_dlen=2 skips Frame 0 and blocks until Frame 1 arrives.
       */
      btl_moc_read_start (self, ssm, BTL_CMD_ENROLL, 1, 2, TRUE,
                          0, -1, 0,
                          fpi_device_get_cancellable (dev),
                          ENROLL_CANCEL_SEND);
      break;

    case ENROLL_STEP_PARSE:
      if (!self->have_reply || rdlen < 2)
        {
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }

      /* 0x10: MCU finger-wait timeout without finger contact -> re-arm silently */
      if (pl[0] == BTL_STATUS_NO_FINGER)
        {
          fpi_ssm_jump_to_state (ssm, ENROLL_STEP_SEND);
          break;
        }

      self->last_capture_us = g_get_monotonic_time ();
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_PRESENT,
                                               FP_FINGER_STATUS_NONE);

      fp_dbg ("0xB0/1 stage=%d -> status=0x%02x cur=%u/%d (rdlen=%u)",
              self->enroll_stage, pl[0],
              rdlen >= 2 ? (guint) pl[1] : 0U,
              self->total_stages, rdlen);

      if (pl[0] == BTL_STATUS_OK)
        {
          gboolean mcu_done;

          /* BetterlifeEngineAdapter.dll 0x18009c3b4: complete iff cur == Max */
          if (rdlen >= 2 && pl[1] >= 1)
            {
              self->completed_stages = CLAMP ((gint) pl[1], 1, self->total_stages);
              mcu_done = ((gint) pl[1] >= self->total_stages);
            }
          else
            {
              self->completed_stages = CLAMP (self->completed_stages + 1,
                                              1, self->total_stages);
              mcu_done = (self->completed_stages >= self->total_stages);
            }

          self->enroll_stage++;
          fpi_device_enroll_progress (dev, self->completed_stages, NULL, NULL);

          if (mcu_done)
            {
              fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
              fpi_ssm_jump_to_state (ssm, ENROLL_COMMIT_SETTLE);
              break;
            }
        }
      else if (pl[0] == BTL_STATUS_DUPLICATE)
        {
          /* 0x12: Finger is already registered in another MCU flash slot */
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
          break;
        }
      else if (pl[0] == BTL_STATUS_SAVE_FAIL ||
               pl[0] == BTL_STATUS_FLASH_ERR ||
               pl[0] == BTL_STATUS_UNSUPPORTED)
        {
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new_msg (pl[0] == BTL_STATUS_UNSUPPORTED
                                                                 ? FP_DEVICE_ERROR_PROTO
                                                                 : FP_DEVICE_ERROR_GENERAL,
                                                                 "MCU enroll error (status 0x%02x)",
                                                                 pl[0]));
          break;
        }
      else
        {
          /* Critical protocol rule: do NOT increment enroll_stage on nonzero status! */
          fpi_device_enroll_progress (dev, self->completed_stages, NULL,
                                      btl_moc_retry_error (pl[0]));
        }

      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_PRESENT);
      fpi_ssm_jump_to_state (ssm, ENROLL_STEP_SETTLE);
      break;

    case ENROLL_COMMIT_SETTLE:
      {
        gint wait_ms = btl_moc_settle_delay_ms (self);
        if (wait_ms > 0)
          fpi_ssm_next_state_delayed (ssm, wait_ms);
        else
          fpi_ssm_next_state (ssm);
        break;
      }

    case ENROLL_COMMIT_SEND:
      {
        FpPrint *print = NULL;
        fpi_device_get_enroll_data (dev, &print);
        if (self->cmd_attempt == 0)
          btl_moc_prepare_enroll_tag (self, print);
        btl_moc_send (self, ssm, BTL_CMD_ENROLL, 2,
                      self->enroll_tag, BTL_TAG_LEN,
                      self->sess, BTL_WRITE_TIMEOUT_MS);
        break;
      }

    case ENROLL_COMMIT_READ:
      /*
       * BetterlifeFingerprintDevice.dll 0x1800160ef: 0xB0/2 reply is always 19
       * bytes {status, u16 slot_id, u8 fuid[16]}; min_dlen=19 skips any 0/1-byte ACK.
       */
      btl_moc_read_start (self, ssm, BTL_CMD_ENROLL, 2, 3 + BTL_FUID_LEN, TRUE,
                          BTL_COMMIT_ATTEMPT_MS, ENROLL_COMMIT_SEND, BTL_COMMIT_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case ENROLL_COMMIT_PARSE:
      if (!self->have_reply || rdlen < 3 + BTL_FUID_LEN)
        {
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      if (pl[0] == BTL_STATUS_DUPLICATE)
        {
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
          break;
        }
      if (pl[0] != BTL_STATUS_OK)
        {
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                 "MCU commit failed (status 0x%02x)",
                                                                 pl[0]));
          break;
        }
      if (rdlen < 3 + BTL_FUID_LEN)
        {
          btl_moc_enroll_fail_cleanup (self, ssm,
                                       fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      else
        {
          FpPrint *print = NULL;
          guint16 slot_id = (guint16) pl[1] | ((guint16) pl[2] << 8);
          const guint8 *fuid = pl + 3;

          self->mcu_enrolling = FALSE;
          self->enrolled_count++;
          fp_dbg ("0xB0/2 template committed to MCU slot %u", slot_id);
          fpi_device_get_enroll_data (dev, &print);
          btl_moc_populate_print (print, fuid, (const gchar *) self->enroll_tag);
          fpi_ssm_mark_completed (ssm);
        }
      break;

    case ENROLL_CANCEL_SEND:
      self->mcu_enrolling = FALSE;
      btl_moc_send_best_effort (self, ssm, BTL_CMD_ENROLL, 3, &zero1, 1);
      break;

    case ENROLL_CANCEL_READ:
      {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, BTL_BULK_IN_CHUNK);
        fpi_usb_transfer_submit (t, 400, NULL, btl_moc_best_effort_cb, NULL);
        break;
      }

    case ENROLL_CANCEL_DRAIN:
      btl_moc_drain_start (self, ssm, 6);
      break;

    case ENROLL_CANCEL_DONE:
      fpi_ssm_mark_failed (ssm,
                           self->cancel_error
                           ? g_steal_pointer (&self->cancel_error)
                           : g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                  "Enrollment cancelled"));
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
btl_moc_enroll_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  FpPrint *print = NULL;

  self->ssm = NULL;
  self->active_send_state = -1;
  g_clear_error (&self->cancel_error);

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
btl_moc_enroll (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  g_clear_error (&self->cancel_error);
  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_enroll_ssm, ENROLL_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_enroll_complete);
}

/* ---- Verify & Identify (0xB1/0 -> async result wait; 0xB1/1 cancel) ------ */

static void
btl_moc_match_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  const guint8 *pl = self->reply_buf;
  guint32 rdlen = self->reply_len;
  static const guint8 zero1 = 0x00;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case MATCH_PRE_CANCEL_ENROLL:
      if (self->mcu_enrolling)
        {
          self->mcu_enrolling = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_ENROLL, 3, &zero1, 1);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case MATCH_PRE_CANCEL_MATCH:
      if (self->mcu_matching)
        {
          self->mcu_matching = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_IDENTIFY, 1, NULL, 0);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case MATCH_PRE_DRAIN:
      btl_moc_drain_start (self, ssm, 8);
      break;

    case MATCH_SETTLE:
      {
        gint wait_ms;

        if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
          {
            fpi_ssm_mark_failed (ssm,
                                 g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                      "Verification cancelled"));
            break;
          }

        wait_ms = btl_moc_settle_delay_ms (self);
        if (wait_ms > 0)
          fpi_ssm_next_state_delayed (ssm, wait_ms);
        else
          fpi_ssm_next_state (ssm);
        break;
      }

    case MATCH_START_SEND:
      if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
        {
          fpi_ssm_mark_failed (ssm,
                               g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                    "Verification cancelled"));
          break;
        }
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_PRESENT);
      self->mcu_matching = TRUE;
      btl_moc_send (self, ssm, BTL_CMD_IDENTIFY, 0, NULL, 0,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case MATCH_WAIT:
      /*
       * BetterlifeFingerprintDevice.dll 0x18001627e: 0xB1/0 emits a 0-byte ACK
       * frame followed after finger contact by a 19-byte result frame
       * {status, u16 slot_id, u8 fuid[16]} for all completion statuses.
       */
      btl_moc_read_start (self, ssm, BTL_CMD_IDENTIFY, 0, 3 + BTL_FUID_LEN, TRUE,
                          0, -1, 0,
                          fpi_device_get_cancellable (dev),
                          MATCH_CANCEL_SEND);
      break;

    case MATCH_PARSE:
      if (!self->have_reply || rdlen < 3 + BTL_FUID_LEN)
        {
          self->mcu_matching = FALSE;
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }

      /* 0x10: MCU finger-wait timeout without finger contact -> re-arm silently */
      if (pl[0] == BTL_STATUS_NO_FINGER)
        {
          fpi_ssm_jump_to_state (ssm, MATCH_START_SEND);
          break;
        }

      self->mcu_matching = FALSE;
      self->last_capture_us = g_get_monotonic_time ();
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_PRESENT,
                                               FP_FINGER_STATUS_NEEDED);
      fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);

      fp_dbg ("0xB1/0 match status=0x%02x (rdlen=%u)", pl[0], rdlen);

      if (pl[0] == BTL_STATUS_OK)
        {
          FpPrint *scan;
          guint16 slot_id;
          const guint8 *fuid;

          if (rdlen < 3 + BTL_FUID_LEN)
            {
              fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
              break;
            }

          slot_id = (guint16) pl[1] | ((guint16) pl[2] << 8);
          fuid = pl + 3;
          fp_dbg ("MCU matched template in slot %u", slot_id);

          scan = fp_print_new (dev);
          btl_moc_populate_print (scan, fuid, NULL);

          if (action == FPI_DEVICE_ACTION_VERIFY)
            {
              FpPrint *target = NULL;
              gboolean ok;

              fpi_device_get_verify_data (dev, &target);
              ok = fp_print_equal (target, scan);
              fpi_device_verify_report (dev,
                                        ok ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                        scan,
                                        NULL);
            }
          else
            {
              GPtrArray *gallery = NULL;
              FpPrint *matched = NULL;

              fpi_device_get_identify_data (dev, &gallery);
              if (gallery)
                {
                  for (guint i = 0; i < gallery->len; i++)
                    {
                      FpPrint *cand = g_ptr_array_index (gallery, i);
                      if (fp_print_equal (cand, scan))
                        {
                          matched = cand;
                          break;
                        }
                    }
                }
              fpi_device_identify_report (dev, matched, scan, NULL);
            }

          fpi_ssm_mark_completed (ssm);
          break;
        }
      else if (pl[0] == BTL_STATUS_DB_EMPTY ||
               pl[0] == BTL_STATUS_NO_MATCH ||
               pl[0] == BTL_STATUS_LEGACY_NO_MATCH)
        {
          /*
           * Clean capture on sensor, finger is not enrolled in MCU flash:
           *   0x20: MCU database currently holds 0 templates
           *   0x21: Clean scan did not match any enrolled template
           *   0x0B: Legacy WinBio no-match code
           */
          if (action == FPI_DEVICE_ACTION_VERIFY)
            fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
          else
            fpi_device_identify_report (dev, NULL, NULL, NULL);

          fpi_ssm_mark_completed (ssm);
          break;
        }
      else if (pl[0] == BTL_STATUS_FLASH_ERR ||
               pl[0] == BTL_STATUS_UNSUPPORTED)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (pl[0] == BTL_STATUS_UNSUPPORTED
                                                         ? FP_DEVICE_ERROR_PROTO
                                                         : FP_DEVICE_ERROR_GENERAL,
                                                         "MCU match error (status 0x%02x)",
                                                         pl[0]));
          break;
        }
      else
        {
          /* Retryable scan quality/position status (0x11, 0x14, 0x30..0x36, etc.) */
          GError *retry = btl_moc_retry_error (pl[0]);
          if (action == FPI_DEVICE_ACTION_VERIFY)
            fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, retry);
          else
            fpi_device_identify_report (dev, NULL, NULL, retry);

          fpi_ssm_mark_completed (ssm);
          break;
        }

    case MATCH_CANCEL_SEND:
      self->mcu_matching = FALSE;
      btl_moc_send_best_effort (self, ssm, BTL_CMD_IDENTIFY, 1, NULL, 0);
      break;

    case MATCH_CANCEL_READ:
      {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, BTL_BULK_IN_CHUNK);
        fpi_usb_transfer_submit (t, 400, NULL, btl_moc_best_effort_cb, NULL);
        break;
      }

    case MATCH_CANCEL_DRAIN:
      btl_moc_drain_start (self, ssm, 6);
      break;

    case MATCH_CANCEL_DONE:
      fpi_ssm_mark_failed (ssm,
                           self->cancel_error
                           ? g_steal_pointer (&self->cancel_error)
                           : g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                  "Verification cancelled"));
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
btl_moc_match_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  self->ssm = NULL;
  self->active_send_state = -1;
  g_clear_error (&self->cancel_error);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
btl_moc_verify_identify (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  g_clear_error (&self->cancel_error);
  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_match_ssm, MATCH_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_match_complete);
}

/* ---- Delete single print & Clear all on-chip storage (0xB2, sub=1) ------- */

static void
btl_moc_del_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  const guint8 *pl = self->reply_buf;
  guint32 rdlen = self->reply_len;
  static const guint8 zero1 = 0x00;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DEL_PRE_CANCEL_ENROLL:
      if (self->mcu_enrolling)
        {
          self->mcu_enrolling = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_ENROLL, 3, &zero1, 1);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case DEL_PRE_CANCEL_MATCH:
      if (self->mcu_matching)
        {
          self->mcu_matching = FALSE;
          btl_moc_send_best_effort (self, ssm, BTL_CMD_IDENTIFY, 1, NULL, 0);
        }
      else
        {
          fpi_ssm_next_state (ssm);
        }
      break;

    case DEL_PRE_DRAIN:
      btl_moc_drain_start (self, ssm, 8);
      break;

    case DEL_SEND:
      btl_moc_send (self, ssm, BTL_CMD_DELETE, 1,
                    self->del_tag, BTL_TAG_LEN,
                    self->sess, BTL_WRITE_TIMEOUT_MS);
      break;

    case DEL_READ:
      btl_moc_read_start (self, ssm, BTL_CMD_DELETE, 1, 1, TRUE,
                          BTL_COMMIT_ATTEMPT_MS, DEL_SEND, BTL_COMMIT_MAX_ATTEMPTS,
                          NULL, -1);
      break;

    case DEL_PARSE:
      if (!self->have_reply || rdlen < 1)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_CLEAR_STORAGE)
        {
          if (pl[0] != BTL_STATUS_OK &&
              pl[0] != BTL_STATUS_ID_NOT_EXIST &&
              pl[0] != BTL_STATUS_DB_EMPTY)
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                             "MCU clear_storage failed (status 0x%02x)",
                                                             pl[0]));
              break;
            }
          self->enrolled_count = 0;
        }
      else if (pl[0] == BTL_STATUS_FLASH_ERR || pl[0] == BTL_STATUS_UNSUPPORTED)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                         "MCU delete failed (status 0x%02x)",
                                                         pl[0]));
          break;
        }
      else if (pl[0] == BTL_STATUS_OK && self->enrolled_count > 0)
        {
          self->enrolled_count--;
        }
      fp_dbg ("0xB2/1 delete status=0x%02x", pl[0]);
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
btl_moc_del_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  self->ssm = NULL;
  self->active_send_state = -1;
  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_CLEAR_STORAGE)
    fpi_device_clear_storage_complete (dev, error);
  else
    fpi_device_delete_complete (dev, error);
}

static void
btl_moc_delete (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);
  FpPrint *print = NULL;
  const gchar *desc = NULL;
  static const guint8 zeros[BTL_TAG_LEN] = { 0 };
  gsize len;

  fpi_device_get_delete_data (dev, &print);
  if (print)
    desc = fp_print_get_description (print);

  /* Safety guard: 32 zero bytes wipes ALL templates on 347d:0302. Never send
   * an all-zero tag during single-finger delete. */
  if (!desc || desc[0] == '\0')
    {
      fp_warn ("Print lacks an on-chip tag description; skipping single-slot MCU delete");
      fpi_device_delete_complete (dev, NULL);
      return;
    }

  memset (self->del_tag, 0, sizeof self->del_tag);
  len = MIN (strlen (desc), BTL_TAG_LEN - 1);
  memcpy (self->del_tag, desc, len);

  if (memcmp (self->del_tag, zeros, BTL_TAG_LEN) == 0)
    {
      fpi_device_delete_complete (dev, NULL);
      return;
    }

  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_del_ssm, DEL_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_del_complete);
}

static void
btl_moc_clear_storage (FpDevice *dev)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (dev);

  memset (self->del_tag, 0, sizeof self->del_tag);
  self->active_send_state = -1;
  self->ssm = fpi_ssm_new (dev, btl_moc_del_ssm, DEL_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_moc_del_complete);
}

/* ---- Object lifecycle & driver registration ------------------------------ */

static void
fpi_device_betterlife347d_moc_finalize (GObject *object)
{
  FpiDeviceBetterlife347dMoc *self = FPI_DEVICE_BETTERLIFE347D_MOC (object);

  OPENSSL_cleanse (self->sess, sizeof self->sess);
  g_clear_pointer (&self->hs, btl_handshake_free);
  g_clear_pointer (&self->module_uid_hex, g_free);
  g_clear_error (&self->cancel_error);

  G_OBJECT_CLASS (fpi_device_betterlife347d_moc_parent_class)->finalize (object);
}

static const FpIdEntry id_table[] = {
  { .vid = 0x347d, .pid = 0x0302 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_betterlife347d_moc_init (FpiDeviceBetterlife347dMoc *self)
{
  self->cancel_state = -1;
  self->active_send_state = -1;
  self->retry_send_state = -1;
  self->total_stages = BTL_DEFAULT_STAGES;
}

static void
fpi_device_betterlife347d_moc_class_init (FpiDeviceBetterlife347dMocClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_betterlife347d_moc_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Blestech Betterlife 347d:0302 MOC Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = BTL_DEFAULT_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->probe = btl_moc_probe;
  dev_class->open = btl_moc_open;
  dev_class->close = btl_moc_close;
  dev_class->enroll = btl_moc_enroll;
  dev_class->verify = btl_moc_verify_identify;
  dev_class->identify = btl_moc_verify_identify;
  dev_class->delete = btl_moc_delete;
  dev_class->clear_storage = btl_moc_clear_storage;

  fpi_device_class_auto_initialize_features (dev_class);
}
