/*
 * Betterlife 347d:0304 fingerprint reader driver for libfprint
 *
 * Image-based (FpImageDevice) driver for the Blestech/Betterlife USB sensor
 * found on generic (Tongfang/Clevo) barebones. The device speaks an SM2/SM3/SM4
 * secure channel; see betterlife347d-proto.c for the framing and handshake.
 * Capture geometry is 96x112, 8bpp. Matching is done host-side by libfprint's
 * built-in NBIS (bozorth3) pipeline.
 *
 * Copyright (C) 2026 huellero project
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

#define FP_COMPONENT "betterlife347d"
#include "fpi-log.h"

#include "drivers_api.h"
#include "betterlife347d-proto.h"

#define BTL_EP_OUT (0x02 | FPI_USB_ENDPOINT_OUT)
#define BTL_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)

/* The B4/0 ack is immediate but the metadata frame that follows can take up to
 * ~2s on hardware (device settling / finger wait). A short read timeout there
 * leaves the metadata pending in the IN endpoint and desyncs every later read,
 * which looked like a device "hang". Wait patiently, like the Windows driver. */
#define BTL_TIMEOUT      4000
#define BTL_DRAIN_TIMEOUT 120
#define BTL_DRAIN_READS   24
#define BTL_HS_RETRIES    8
/* Finger detection is done by the DEVICE: after B4/0 it pushes a metadata frame
 * (b4/0, dlen>=9) only once a finger is present, exactly like the Windows driver.
 * So the host sends B4/0 and does a long blocking read for that metadata instead
 * of continuously capturing images to guess - far fewer operations, which this
 * weak bus-powered firmware needs to avoid wedging. BTL_WAIT_FINGER_MS also acts
 * as the keepalive interval (resend B4/0 if no finger yet); no metadata for
 * BTL_WAIT_OFF_MS means the finger has lifted. */
#define BTL_WAIT_FINGER_MS 4000
#define BTL_WAIT_OFF_MS    2000

/* The full 96x112 image is fetched in a SINGLE B4/1 request of its byte size.
 * Splitting it into two chunks (as the Windows driver does) made the device
 * return garbage for the second chunk; one read returns the whole clean frame. */
#define BTL_IMG_REQ 0x2a00     /* == BTL_IMG_SIZE (10752) */

/* Image resolution in pixels/mm. mindtct needs this to size ridges; left unset
 * (0) it extracts no usable minutiae and every match scores 0. ~500 DPI matches
 * the observed ridge spacing (~10-12 ridges across 96 px). ponytail: tunable. */
#define BTL_PPMM 19.685

/* Receive reassembly buffer: one framed image plus header/pad/crc. */
#define BTL_RX_CAP 16384

enum open_states {
  OPEN_DRAIN,
  OPEN_A0_SEND,
  OPEN_A0_READ,
  OPEN_A2_SEND,
  OPEN_A2_READ,
  OPEN_DERIVE,
  OPEN_NUM_STATES,
};

enum capture_states {
  CAP_B4_0_SEND,
  CAP_WAIT_META,
  CAP_B4_1_SEND,
  CAP_B4_1_READ,
  CAP_SUBMIT,
  CAP_NUM_STATES,
};

struct _FpiDeviceBetterlife347d
{
  FpImageDevice parent;

  FpiSsm       *ssm;
  BtlHandshake *hs;
  guint8        sess[BTL_SESSKEY_LEN];
  gboolean      have_session;

  guint8        pub[65];
  gint          hs_retries;
  gint          drain_left;

  guint8        tx[256];
  guint8        rx[BTL_RX_CAP];
  gsize         rx_got;
  gint          rx_want_frames;

  guint8        img[BTL_IMG_SIZE];
  gsize         img_got;

  gboolean      awaiting_off;
  gboolean      deactivating;
};
G_DECLARE_FINAL_TYPE (FpiDeviceBetterlife347d, fpi_device_betterlife347d, FPI,
                      DEVICE_BETTERLIFE347D, FpImageDevice);
G_DEFINE_TYPE (FpiDeviceBetterlife347d, fpi_device_betterlife347d, FP_TYPE_IMAGE_DEVICE);

/* ---- low-level send / framed-read helpers ---------------------------------- */

static void
btl_send (FpiDeviceBetterlife347d *self, FpiSsm *ssm, guint8 cmd, guint8 sub,
          const guint8 *data, gsize dlen, const guint8 *key,
          FpiUsbTransferCallback cb)
{
  FpiUsbTransfer *t;
  gssize n = btl_frame_build (self->tx, sizeof self->tx, cmd, sub, data, dlen, key, NULL);

  if (n < 0)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->ssm = ssm;
  t->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (t, BTL_EP_OUT, self->tx, n, NULL);
  fpi_usb_transfer_submit (t, BTL_TIMEOUT, fpi_device_get_cancellable (FP_DEVICE (self)),
                           cb, NULL);
}

static void btl_frame_read_submit (FpiDeviceBetterlife347d *self, FpiSsm *ssm);

/* Count complete 0xAA frames in buf using the plaintext length fields only
 * (the body is encrypted, but the outer length is not). A single bulk IN
 * transfer may carry more than one frame: the B4/0 ack and metadata often
 * arrive coalesced, so reads must stop on a frame count, not a byte count. */
static gint
btl_count_frames (const guint8 *buf, gsize got)
{
  gsize off = 0;
  gint n = 0;

  while (off + 5 <= got)
    {
      guint32 len;
      gsize flen;

      if (buf[off] != 0xAA)
        break;
      len = buf[off + 1] | buf[off + 2] << 8 | buf[off + 3] << 16 | (guint32) buf[off + 4] << 24;
      flen = (gsize) len + 5;
      if (off + flen > got)
        break;
      off += flen;
      n++;
    }
  return n;
}

static void
btl_frame_read_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  self->rx_got += transfer->actual_length;

  if (btl_count_frames (self->rx, self->rx_got) >= self->rx_want_frames ||
      transfer->actual_length == 0 ||
      self->rx_got >= sizeof self->rx)
    {
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  btl_frame_read_submit (self, transfer->ssm);
}

static void
btl_frame_read_submit (FpiDeviceBetterlife347d *self, FpiSsm *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (t, BTL_EP_IN, self->rx + self->rx_got,
                                   sizeof self->rx - self->rx_got, NULL);
  fpi_usb_transfer_submit (t, BTL_TIMEOUT, fpi_device_get_cancellable (FP_DEVICE (self)),
                           btl_frame_read_cb, NULL);
}

/* Read until want_frames complete frames are buffered (see btl_count_frames). */
static void
btl_frame_read_start (FpiDeviceBetterlife347d *self, FpiSsm *ssm, gint want_frames)
{
  self->rx_got = 0;
  self->rx_want_frames = want_frames;
  btl_frame_read_submit (self, ssm);
}

static void btl_meta_submit (FpiDeviceBetterlife347d *self, FpiSsm *ssm);

/* Finger-detect reader (Windows model): after B4/0, the device returns the ack
 * immediately and then pushes the metadata frame WHEN A FINGER IS PRESENT. So we
 * block-read waiting for a second frame (ack + metadata = finger present):
 *   - two frames buffered  -> finger present: capture the image, or if we are
 *                             waiting for lift, keep checking;
 *   - timeout (ack only)   -> no metadata: no finger. While awaiting a finger this
 *                             is a keepalive (resend B4/0); while awaiting lift it
 *                             means the finger was removed, so end the cycle;
 *   - other error          -> propagate (e.g. cancellation). */
static void
btl_meta_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);
  FpImageDevice *idev = FP_IMAGE_DEVICE (dev);

  if (self->deactivating)
    {
      g_clear_error (&error);
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }
  if (error)
    {
      if (!g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
        {
          fpi_ssm_mark_failed (transfer->ssm, error);
          return;
        }
      g_clear_error (&error);
      if (self->awaiting_off)
        {
          fpi_image_device_report_finger_status (idev, FALSE);
          fpi_ssm_mark_completed (transfer->ssm);
        }
      else
        {
          fpi_ssm_jump_to_state (transfer->ssm, CAP_B4_0_SEND);
        }
      return;
    }

  self->rx_got += transfer->actual_length;

  if (btl_count_frames (self->rx, self->rx_got) >= 2)
    {
      /* finger present */
      fpi_ssm_jump_to_state (transfer->ssm,
                             self->awaiting_off ? CAP_B4_0_SEND : CAP_B4_1_SEND);
      return;
    }
  if (self->rx_got >= sizeof self->rx)
    {
      fpi_ssm_jump_to_state (transfer->ssm, CAP_B4_0_SEND);
      return;
    }
  btl_meta_submit (self, transfer->ssm);
}

static void
btl_meta_submit (FpiDeviceBetterlife347d *self, FpiSsm *ssm)
{
  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));
  guint timeout = self->awaiting_off ? BTL_WAIT_OFF_MS : BTL_WAIT_FINGER_MS;

  t->ssm = ssm;
  fpi_usb_transfer_fill_bulk_full (t, BTL_EP_IN, self->rx + self->rx_got,
                                   sizeof self->rx - self->rx_got, NULL);
  fpi_usb_transfer_submit (t, timeout, fpi_device_get_cancellable (FP_DEVICE (self)),
                           btl_meta_cb, NULL);
}

/* Consume the frame currently in self->rx: decrypt and append its payload to
 * the image buffer. Returns the payload length appended, or -1 on error. */
static gssize
btl_consume_chunk (FpiDeviceBetterlife347d *self)
{
  guint8 cmd, sub;
  guint32 dlen;
  const guint8 *pl = btl_frame_parse (self->rx, self->rx_got, self->sess, &cmd, &sub, &dlen);

  if (!pl || cmd != 0xB4 || dlen == 0 || self->img_got + dlen > BTL_IMG_SIZE)
    return -1;

  memcpy (self->img + self->img_got, pl, dlen);
  self->img_got += dlen;
  return dlen;
}

/* ---- open: drain + SM2/SM3/SM4 handshake ----------------------------------- */

static void
btl_drain_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);
  gboolean timed_out = error &&
                       g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);

  /* Drain tolerates timeouts/short reads: the goal is only to flush any stale
   * session bytes left in the IN endpoint before handshaking. Stop immediately
   * once a drain read times out with 0 bytes so open() stays ~120 ms. */
  g_clear_error (&error);

  if ((timed_out && transfer->actual_length <= 0) || --self->drain_left <= 0)
    {
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  FpiUsbTransfer *t = fpi_usb_transfer_new (FP_DEVICE (self));
  t->ssm = transfer->ssm;
  fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, sizeof self->rx);
  fpi_usb_transfer_submit (t, BTL_DRAIN_TIMEOUT,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           btl_drain_cb, NULL);
}

/* A0 init payload observed on the wire before the SM2 exchange. */
static const guint8 btl_a0_init[] = { 1, 0, 1, 1, 3, 0x11, 0 };

static void
btl_open_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_DRAIN:
      {
        FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
        self->drain_left = BTL_DRAIN_READS;
        t->ssm = ssm;
        fpi_usb_transfer_fill_bulk (t, BTL_EP_IN, sizeof self->rx);
        fpi_usb_transfer_submit (t, BTL_DRAIN_TIMEOUT,
                                 fpi_device_get_cancellable (dev), btl_drain_cb, NULL);
        break;
      }

    case OPEN_A0_SEND:
      btl_send (self, ssm, 0xA0, 0, btl_a0_init, sizeof btl_a0_init, NULL,
                fpi_ssm_usb_transfer_cb);
      break;

    case OPEN_A0_READ:
      btl_frame_read_start (self, ssm, 1);
      break;

    case OPEN_A2_SEND:
      if (!btl_handshake_pubkey (self->hs, self->pub))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          break;
        }
      btl_send (self, ssm, 0xA2, 0, self->pub, sizeof self->pub, NULL,
                fpi_ssm_usb_transfer_cb);
      break;

    case OPEN_A2_READ:
      btl_frame_read_start (self, ssm, 1);
      break;

    case OPEN_DERIVE:
      {
        guint8 cmd, sub;
        guint32 dlen;
        const guint8 *pl = btl_frame_parse (self->rx, self->rx_got, NULL, &cmd, &sub, &dlen);

        if (pl && dlen >= 112 &&
            btl_handshake_derive (self->hs, pl, dlen, self->sess))
          {
            self->have_session = TRUE;
            fpi_ssm_mark_completed (ssm);
            break;
          }

        if (self->hs_retries++ < BTL_HS_RETRIES)
          {
            fp_dbg ("handshake attempt failed, retrying (%d)", self->hs_retries);
            fpi_ssm_jump_to_state (ssm, OPEN_DRAIN);
            break;
          }
        fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
        break;
      }

    default:
      g_assert_not_reached ();
    }
}

static void
btl_open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  self->ssm = NULL;
  g_clear_pointer (&self->hs, btl_handshake_free);
  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
btl_dev_open (FpImageDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);
  GError *error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                     0, 0, &error))
    {
      fpi_image_device_open_complete (dev, error);
      return;
    }

  self->hs = btl_handshake_new ();
  if (!self->hs)
    {
      fpi_image_device_open_complete (dev, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  self->have_session = FALSE;
  self->hs_retries = 0;
  self->ssm = fpi_ssm_new (FP_DEVICE (dev), btl_open_ssm, OPEN_NUM_STATES);
  fpi_ssm_start (self->ssm, btl_open_complete);
}

static void
btl_dev_close (FpImageDevice *dev)
{
  GError *error = NULL;

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, &error);
  fpi_image_device_close_complete (dev, error);
}

/* ---- capture: B4 sequence + finger detection ------------------------------- */

static const guint8 btl_b4_zero[4] = { 0, 0, 0, 0 };
static const guint8 btl_b4_img[4] = { BTL_IMG_REQ & 0xff, BTL_IMG_REQ >> 8, 0, 0 };

static void
btl_submit_image (FpImageDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);
  FpImage *img = fp_image_new (BTL_IMG_W, BTL_IMG_H);

  img->ppmm = BTL_PPMM;
  memcpy (img->data, self->img, BTL_IMG_SIZE);
  fpi_image_device_image_captured (dev, img);
}

static void
btl_capture_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_B4_0_SEND:
      self->img_got = 0;
      btl_send (self, ssm, 0xB4, 0, btl_b4_zero, sizeof btl_b4_zero, self->sess,
                fpi_ssm_usb_transfer_cb);
      break;

    case CAP_WAIT_META:
      /* Block waiting for the device's finger-detect metadata (see btl_meta_cb);
       * the callback drives the next transition. */
      self->rx_got = 0;
      btl_meta_submit (self, ssm);
      break;

    case CAP_B4_1_SEND:
      btl_send (self, ssm, 0xB4, 1, btl_b4_img, sizeof btl_b4_img, self->sess,
                fpi_ssm_usb_transfer_cb);
      break;

    case CAP_B4_1_READ:
      btl_frame_read_start (self, ssm, 1);
      break;

    case CAP_SUBMIT:
      if (btl_consume_chunk (self) < 0 || self->img_got < BTL_IMG_SIZE)
        {
          /* Bad/short image read: go back and wait for the finger again. */
          fpi_ssm_jump_to_state (ssm, CAP_B4_0_SEND);
          break;
        }
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      btl_submit_image (FP_IMAGE_DEVICE (dev));
      /* Now wait for the finger to lift before this cycle ends, so the next
       * enroll stage is a distinct touch. */
      self->awaiting_off = TRUE;
      fpi_ssm_jump_to_state (ssm, CAP_B4_0_SEND);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
btl_capture_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  self->ssm = NULL;

  if (self->deactivating)
    fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), error);
  else if (error)
    fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
}

static void
btl_dev_activate (FpImageDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  self->deactivating = FALSE;
  fpi_image_device_activate_complete (dev, NULL);
}

static void
btl_dev_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    {
      self->awaiting_off = FALSE;
      self->ssm = fpi_ssm_new (FP_DEVICE (dev), btl_capture_ssm, CAP_NUM_STATES);
      fpi_ssm_start (self->ssm, btl_capture_complete);
    }
}

static void
btl_dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceBetterlife347d *self = FPI_DEVICE_BETTERLIFE347D (dev);

  self->deactivating = TRUE;
  if (self->ssm == NULL)
    fpi_image_device_deactivate_complete (dev, NULL);
}

/* ---- registration ---------------------------------------------------------- */

static const FpIdEntry id_table[] = {
  { .vid = 0x347d, .pid = 0x0304, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_betterlife347d_init (FpiDeviceBetterlife347d *self)
{
}

static void
fpi_device_betterlife347d_class_init (FpiDeviceBetterlife347dClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Blestech Betterlife 347d:0304";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* This driver polls the sensor continuously to detect a finger; that keeps the
   * device "active" the whole time, which libfprint's thermal model otherwise
   * reads as overheating and disables mid-operation. The hardware tolerates
   * continuous polling, so declare it always-on. */
  dev_class->temp_hot_seconds = -1;

  img_class->img_width = BTL_IMG_W;
  img_class->img_height = BTL_IMG_H;
  /* This 96x112 sensor yields only ~4 minutiae, far too few for NBIS/bozorth3
   * (every match scored 0). Use the SIGFM (SIFT) matcher when built against a
   * SIGFM-capable tree (e.g. libfprint-CS9711), falling back to NBIS threshold
   * only so vanilla upstream trees still compile cleanly for 347d:0302 MOC. */
#if defined(__has_include) && __has_include("sigfm/sigfm.h")
  img_class->algorithm = FPI_DEVICE_ALGO_SIGFM;
  img_class->score_threshold = 20;
#else
  img_class->bz3_threshold = 12;
#endif

  img_class->img_open = btl_dev_open;
  img_class->img_close = btl_dev_close;
  img_class->activate = btl_dev_activate;
  img_class->change_state = btl_dev_change_state;
  img_class->deactivate = btl_dev_deactivate;
}
