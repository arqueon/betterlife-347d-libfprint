# betterlife-347d-libfprint

[![CI](https://github.com/arqueon/betterlife-347d-libfprint/actions/workflows/ci.yml/badge.svg)](https://github.com/arqueon/betterlife-347d-libfprint/actions/workflows/ci.yml)
[![AUR](https://img.shields.io/aur/version/libfprint-betterlife-347d-git)](https://aur.archlinux.org/packages/libfprint-betterlife-347d-git)
[![License: LGPL-2.1-or-later](https://img.shields.io/badge/License-LGPL--2.1--or--later-blue.svg)](LICENSE)

> **Español:** Lee la documentación completa en [`README.es.md`](README.es.md).

Native Linux **`libfprint-2`** drivers for **Blestech / Shenzhen Betterlife (`btlfp`)** USB fingerprint sensors:

| USB ID | Model | Mode | `libfprint` Driver | Matching Engine |
|--------|-------|------|--------------------|-----------------|
| **`347d:0302`** | `btlfp Betterlife Fingerprint` (chip `0x5f83`, 112×96) | **Match-On-Chip (MOC)** | `betterlife347d_moc` (`FpDevice`) | On-chip MCU flash (10 template slots, 7 enroll stages) |
| **`347d:0304`** | `btlfp Betterlife Fingerprint` (96×112) | **Match-On-Host (MOH)** | `betterlife347d` (`FpImageDevice`) | Host-side **SIGFM** SIFT matcher (`libfprint-CS9711`, OpenCV 4/5) |

Integrates out-of-the-box with **`fprintd`**, **PAM** (`sudo`, `polkit-1`, GDM/SDDM/greetd, DankMaterialShell, GNOME/KDE lockscreens), and multi-reader setups alongside **ZKTeco ZK9500 (`1b55:0124`)** and **Chipsailing CS9711 (`2541:0236`)**.

---

## Quick Start

### 1. Arch Linux / CachyOS / Manjaro / EndeavourOS (AUR)

Install directly from the official AUR package **`libfprint-betterlife-347d-git`** (includes full `347d:0302` MOC + `347d:0304` MOH-SIGFM + `CS9711` OpenCV 4/5 support):

```bash
paru -S libfprint-betterlife-347d-git fprintd
# or:
yay -S libfprint-betterlife-347d-git fprintd
```

- **OpenCV-free variant (`347d:0302` MOC only):** Build [`packaging/arch-upstream/PKGBUILD`](packaging/arch-upstream/PKGBUILD) against vanilla upstream `freedesktop.org/libfprint` without OpenCV.
- **3-family unified variant (Betterlife `347d` + ZKTeco `ZK9500` + Chipsailing `CS9711`):** Run `./build-pkg.sh` from a clone of this repository and install the generated `.pkg.tar.zst` with `sudo pacman -U`.

### 2. Debian / Ubuntu / Fedora / openSUSE (Generic Linux Installer)

Install build dependencies first:

- **Debian / Ubuntu 24.04+:**
  ```bash
  sudo apt-get update && sudo apt-get install -y \
    build-essential cmake git meson ninja-build pkg-config python3 python3-gi \
    libglib2.0-dev libgusb-dev libusb-1.0-0-dev libpixman-1-dev \
    libnss3-dev libssl-dev libgudev-1.0-dev libudev-dev udev \
    libcairo2-dev libopencv-dev fprintd libpam-fprintd
  ```
- **Fedora 40+:**
  ```bash
  sudo dnf install -y gcc gcc-c++ cmake git meson ninja-build pkgconf-pkg-config \
    python3 python3-gobject glib2-devel libgusb-devel libusb1-devel pixman-devel \
    openssl-devel libgudev-devel systemd-devel cairo-devel opencv-devel fprintd fprintd-pam
  ```

Then clone and run the automated installer:

```bash
git clone https://github.com/arqueon/betterlife-347d-libfprint.git
cd betterlife-347d-libfprint
./scripts/install-generic-linux.sh
# Or without OpenCV (vanilla upstream libfprint, recommended if you only use 347d:0302 MOC):
./scripts/install-generic-linux.sh --upstream-only
```

---

## Enrollment, Verification & Multi-Reader CLI (`betterlife-fprintd`)

When multiple fingerprint sensors are connected at once, standard `fprintd-enroll` / `fprintd-verify` bind strictly to the first D-Bus device (`/net/reactivated/Fprint/Device/0`). This project installs `betterlife-fprintd` (`fprintd-multi`), which targets the Betterlife reader directly by D-Bus name:

```bash
# Show all connected sensors, enrolled fingers, and which sensor PAM currently selects
betterlife-fprintd status

# Passive read-only USB diagnostic probe (firmware version, scheme, chip ID, MCU slots)
betterlife347d-probe

# Enroll a finger on Betterlife 347d:0302 (1 duplicate-check touch + 7 MOC stages = 8 touches)
betterlife-fprintd enroll right-index-finger

# Verify against Betterlife 347d:0302 / 347d:0304
betterlife-fprintd verify right-index-finger

# Mirror the same enrolled fingers from another connected reader so PAM selects Betterlife
betterlife-fprintd enroll --sync
```

---

## Wire Protocol & Security Architecture (`347d:0302` & `347d:0304`)

Both `347d:0302` and `347d:0304` communicate over Full-Speed USB Bulk `EP 0x02 OUT` / `EP 0x81 IN` (`wMaxPacketSize = 64`) using a framed (`0xAA | len32 | nonce16 | body | crc32`) encrypted channel, where `body = 0x4C | cmd | sub | 0 0 0 | dlen32 | data | pad16`:

1. **Plaintext Discovery (`0xA0`, `0xA1`):**
   - `0xA0`: Queries firmware state/version (`[state=0x01, proj_le16, v0, v1, v2, v3]`, e.g. `proj=0x0f00 V1.0.0.0`).
   - `0xA1`: Queries module scheme (`0x10` = Match-On-Chip on `347d:0302`; `0x11` = Match-On-Host on `347d:0304`).
2. **SM2 / SM3 / SM4 Ephemeral Session Handshake (`0xA2`):**
   - Host generates an ephemeral **SM2** keypair (`GM/T 0003.5-2012` curve via `OpenSSL 3`) and sends its 65-byte uncompressed public key (`0x04 || Xh || Yh`).
   - Sensor responds with its ephemeral public key `(Xm, Ym)`, 32-byte **SM3** MAC, and 16-byte masked session key `encSess`.
   - Both sides compute ECDH shared point `(Sx, Sy)`, derive `KDF = SM3(Sx || Sy || 00000001)`, unmask `sess = encSess ^ KDF[0..15]`, and verify `MAC == SM3(Sx || sess || Sy)`.
   - Every subsequent encrypted frame derives a per-frame **SM4-ECB** key `framekey = SM4-ECB-encrypt(sess, nonce16)`.
3. **Match-On-Chip Operations (`347d:0302`):**
   - `0xC0`: Reads unique silicon Module UID (exposed as `FpDevice` `device-id`).
   - `0xC1`: Reads chip ID (`0x5f83`) and sensor dimensions (`112×96`).
   - `0xB3, sub=0`: Queries `(enrolled_count, max_capacity)` (`10` on-chip flash slots).
   - `0xB0, sub=0/1/2/3`: Multi-stage on-chip enrollment (`7` native stages after `libfprint`'s `DUPLICATES_CHECK` touch = `8` total touches):
     - `0xB0/0` (`Enroll Start`): returns 2-byte `{status, max_stages=7}`.
     - `0xB0/1` (`Enroll Step`): sends 1-byte `stage` (`1..7`, incremented **only** on `status == 0x00`); MCU emits an immediate 1-byte ACK (`pl[0] = stage`) followed after finger contact by a 2-byte `{status, cur}` result (`0x12` duplicate, `0x14`/`0x35`/`0x37` partial/overlap center-finger retry, `0x11`/`0x30` too-short retry, 450 ms inter-touch settle pacing).
     - `0xB0/2` (`Enroll Commit`): sends 32-byte user tag (`2000 ms × 4` synchronous retransmit budget) and receives 19-byte `{status, u16 slot_id, u8 fuid[16]}`.
     - `0xB0/3` (`Enroll Cancel`): aborts active MCU enrollment cleanly.
   - `0xB1, sub=0/1`: On-chip 1:N template identification (0-byte immediate ACK followed after finger contact by 19-byte `{status, u16 slot_id, u8 fuid[16]}`: `0x00` match, `0x20` empty MCU DB / `0x21` clean non-match, or `0x11`/`0x30..0x37` retry status) and `0xB1/1` clean cancellation.
   - `0xB2, sub=1`: Single-template deletion (32-byte user tag) or full MCU storage clear (32 zero bytes via `fprintd` `clear_storage`).

### Hardware Safety Invariant

Firmware-restore (`0xD0`), firmware-update (`0xD1`), bootloader mode-switch (`0xD2`), and JTAG control (`0xC3`) commands are **never** defined or transmitted anywhere in this codebase.

---

## Credits & License

- **`betterlife347d_moc.c` (`347d:0302` MOC driver), `betterlife347d-probe.c`, `fprintd-multi`, CRC/bounds hardening & Arch/Linux packaging:** Copyright (C) 2026 Rubén García Sánchez (`arqueon`) & contributors.
- **`betterlife347d.c` (`347d:0304` MOH driver) & `betterlife347d-proto` / `sm3` / `sm4` cryptographic framing:** Copyright (C) 2026 `huellero` project ([Light-log/betterlife-347d-0304-fingerprint-linux](https://github.com/Light-log/betterlife-347d-0304-fingerprint-linux)).
- Licensed under **GNU Lesser General Public License v2.1 or later (`LGPL-2.1-or-later`)**; see [`LICENSE`](LICENSE).
