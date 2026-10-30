# betterlife-347d-libfprint (Español)

[![CI](https://github.com/arqueon/betterlife-347d-libfprint/actions/workflows/ci.yml/badge.svg)](https://github.com/arqueon/betterlife-347d-libfprint/actions/workflows/ci.yml)
[![AUR](https://img.shields.io/aur/version/libfprint-betterlife-347d-git)](https://aur.archlinux.org/packages/libfprint-betterlife-347d-git)
[![Licencia: LGPL-2.1-or-later](https://img.shields.io/badge/License-LGPL--2.1--or--later-blue.svg)](LICENSE)

> **English:** Read the English documentation in [`README.md`](README.md).

Drivers nativos de **`libfprint-2`** en Linux para los lectores USB de huella dactilar **Blestech / Shenzhen Betterlife (`btlfp`)**:

| USB ID | Modelo | Modo | Driver `libfprint` | Motor de coincidencia |
|--------|--------|------|--------------------|-----------------------|
| **`347d:0302`** | `btlfp Betterlife Fingerprint` (chip `0x5f83`, 112×96) | **Match-On-Chip (MOC)** | `betterlife347d_moc` (`FpDevice`) | Flash interna del MCU (10 ranuras, 7 etapas de registro) |
| **`347d:0304`** | `btlfp Betterlife Fingerprint` (96×112) | **Match-On-Host (MOH)** | `betterlife347d` (`FpImageDevice`) | Matcher **SIGFM** SIFT en host (`libfprint-CS9711`, OpenCV 4/5) |

Funciona directamente con **`fprintd`**, **PAM** (`sudo`, `polkit-1`, GDM/SDDM/greetd, DankMaterialShell, pantallas de bloqueo de GNOME/KDE) y configuraciones multi-lector junto con **ZKTeco ZK9500 (`1b55:0124`)** y **Chipsailing CS9711 (`2541:0236`)**.

---

## Instalación rápida

### 1. Arch Linux / CachyOS / Manjaro / EndeavourOS (AUR)

Instala directamente desde el paquete oficial en AUR **`libfprint-betterlife-347d-git`** (incluye soporte completo para `347d:0302` MOC + `347d:0304` MOH-SIGFM + `CS9711` con OpenCV 4 y 5):

```bash
paru -S libfprint-betterlife-347d-git fprintd
# o con yay:
yay -S libfprint-betterlife-347d-git fprintd
```

- **Variante ligera sin OpenCV (`347d:0302` MOC):** Compila [`packaging/arch-upstream/PKGBUILD`](packaging/arch-upstream/PKGBUILD) sobre `freedesktop.org/libfprint` oficial sin requerir OpenCV.
- **Paquete unificado de 3 familias (Betterlife `347d` + ZKTeco `ZK9500` + Chipsailing `CS9711`):** Ejecuta `./build-pkg.sh` e instala el `.pkg.tar.zst` generado con `sudo pacman -U`.

### 2. Debian / Ubuntu / Fedora / openSUSE (instalador genérico)

```bash
git clone https://github.com/arqueon/betterlife-347d-libfprint.git
cd betterlife-347d-libfprint
./scripts/install-generic-linux.sh
# O sin OpenCV (sobre libfprint upstream puro, ideal si solo usas el modelo MOC 347d:0302):
./scripts/install-generic-linux.sh --upstream-only
```

---

## Registro, verificación y operación multi-lector (`betterlife-fprintd`)

Cuando hay más de un lector conectado a la vez, `fprintd-enroll` y `fprintd-verify` usan únicamente el primer lector en D-Bus. Usa `betterlife-fprintd` (`fprintd-multi`) para dirigir cada operación directamente al lector Betterlife:

```bash
# Ver todos los lectores conectados, huellas registradas y lector activo en PAM
betterlife-fprintd status

# Sonda diagnóstica pasiva por USB (versión de firmware, esquema, chip ID y slots en flash)
betterlife347d-probe

# Registrar una huella en Betterlife 347d:0302 (1 toque anti-duplicado + 7 etapas MOC = 8 toques)
betterlife-fprintd enroll right-index-finger

# Verificar la huella contra el lector Betterlife
betterlife-fprintd verify right-index-finger

# Sincronizar los mismos dedos registrados en otro lector conectado para que PAM elija Betterlife
betterlife-fprintd enroll --sync
```

---

## Invariante de seguridad de hardware

Los comandos de restauración de firmware (`0xD0`), actualización de firmware (`0xD1`), salto a bootloader (`0xD2`) y control JTAG (`0xC3`) **jamás** se definen ni se transmiten en este código.

---

## Créditos y licencia

- **`betterlife347d_moc.c` (driver MOC `347d:0302`), `betterlife347d-probe.c`, `fprintd-multi`, endurecimiento CRC/límites y empaquetado Arch/Linux:** Copyright (C) 2026 Rubén García Sánchez (`arqueon`) y colaboradores.
- **`betterlife347d.c` (driver MOH `347d:0304`) y canal criptográfico `betterlife347d-proto` / `sm3` / `sm4`:** Copyright (C) 2026 proyecto `huellero` ([Light-log/betterlife-347d-0304-fingerprint-linux](https://github.com/Light-log/betterlife-347d-0304-fingerprint-linux)).
- Distribuido bajo **GNU Lesser General Public License v2.1 o posterior (`LGPL-2.1-or-later`)**; véase [`LICENSE`](LICENSE).
