#!/usr/bin/env bash
# Generic Meson/Ninja builder and installer for Debian/Ubuntu, Fedora, openSUSE, etc.
# Default: builds on top of archeYR/libfprint-CS9711 (SIGFM + OpenCV 4/5) so both
#   347d:0302 (MOC) and 347d:0304 (MOH 96x112 SIGFM) + CS9711 (2541:0236) work.
# --upstream-only: builds against vanilla upstream freedesktop libfprint (no OpenCV;
#   full Match-On-Chip support for 347d:0302).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${BETTERLIFE_WORKDIR:-/tmp/betterlife-347d-libfprint-generic}"
UPSTREAM_ONLY=0
PREFIX="/usr"
LIBDIR=""

usage() {
  cat <<'EOF'
Usage: ./scripts/install-generic-linux.sh [--upstream-only] [--prefix /usr] [--libdir lib/x86_64-linux-gnu]

Options:
  --upstream-only       Build against vanilla upstream freedesktop libfprint without OpenCV/SIGFM
                        (recommended if you only have 347d:0302 Match-On-Chip and do not want OpenCV).
                        By default, builds with SIGFM support for both 347d:0302 (MOC) and 347d:0304 (MOH).
  --prefix PATH         Installation prefix (default: /usr so system fprintd picks up libfprint-2.so.2).
  --libdir DIR          Override library subdir if needed (auto-detected via pkg-config otherwise).
  -h, --help            Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upstream-only) UPSTREAM_ONLY=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --libdir) LIBDIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${LIBDIR}" ]]; then
  sys_libdir="$(pkg-config --variable=libdir glib-2.0 2>/dev/null || true)"
  if [[ -n "${sys_libdir}" && "${sys_libdir}" == "${PREFIX}/"* ]]; then
    LIBDIR="${sys_libdir#${PREFIX}/}"
  elif [[ -d "/usr/lib/x86_64-linux-gnu" ]]; then
    LIBDIR="lib/x86_64-linux-gnu"
  elif [[ -d "/usr/lib64" && ! -L "/usr/lib64" ]]; then
    LIBDIR="lib64"
  else
    LIBDIR="lib"
  fi
fi

echo "==> Building in ${WORK_DIR} (prefix=${PREFIX}, libdir=${LIBDIR}, upstream_only=${UPSTREAM_ONLY})..."
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

if [[ "${UPSTREAM_ONLY}" -eq 1 ]]; then
  git clone --depth 1 https://gitlab.freedesktop.org/libfprint/libfprint.git "${WORK_DIR}/libfprint"
  patch -d "${WORK_DIR}/libfprint" -Np1 -i "${REPO_DIR}/patches/0001-upstream-libfprint-betterlife347d.patch"
else
  git clone --depth 1 --branch cs9711-rebase https://github.com/archeYR/libfprint-CS9711.git "${WORK_DIR}/libfprint"
  patch -d "${WORK_DIR}/libfprint" -Np1 -i "${REPO_DIR}/patches/0001-betterlife347d-cs9711.patch"
fi

for _f in betterlife347d_moc.c betterlife347d.c betterlife347d-proto.c betterlife347d-proto.h sm3.c sm3.h sm4.c sm4.h; do
  install -Dm644 "${REPO_DIR}/drivers/betterlife347d/${_f}" \
    "${WORK_DIR}/libfprint/libfprint/drivers/betterlife347d/${_f}"
done

GIR_OPT="-Dintrospection=false"
if command -v g-ir-scanner >/dev/null 2>&1; then
  GIR_OPT="-Dintrospection=true"
fi

meson setup "${WORK_DIR}/build" "${WORK_DIR}/libfprint" \
  --prefix="${PREFIX}" \
  --libdir="${LIBDIR}" \
  --buildtype=release \
  "${GIR_OPT}" \
  -Dudev_hwdb=enabled \
  -Dinstalled-tests=false \
  -Ddoc=false \
  -Dgtk-examples=false

meson compile -C "${WORK_DIR}/build"
meson test -C "${WORK_DIR}/build" --suite unit-tests --print-errorlogs

"${WORK_DIR}/build/libfprint/fprint-list-supported-devices" | grep -q "347d:0302"
"${WORK_DIR}/build/libfprint/fprint-list-supported-devices" | grep -q "347d:0304"

DRV_DIR="${REPO_DIR}/drivers/betterlife347d"
# shellcheck disable=SC2046
cc -O2 -Wall -Wextra -I"${DRV_DIR}" \
  "${REPO_DIR}/tools/betterlife347d-probe.c" \
  "${DRV_DIR}/betterlife347d-proto.c" \
  "${DRV_DIR}/sm3.c" \
  "${DRV_DIR}/sm4.c" \
  -o "${WORK_DIR}/betterlife347d-probe" \
  $(pkg-config --cflags --libs glib-2.0 libusb-1.0 openssl)

echo "==> Installing library, udev rules, and helper tools (requires sudo)..."
sudo meson install -C "${WORK_DIR}/build"
sudo install -Dm755 "${WORK_DIR}/betterlife347d-probe" "${PREFIX}/bin/betterlife347d-probe"
sudo install -Dm755 "${REPO_DIR}/tools/fprintd-multi" "${PREFIX}/bin/fprintd-multi"
sudo ln -sf fprintd-multi "${PREFIX}/bin/betterlife-fprintd"
sudo install -Dm644 "${REPO_DIR}/udev/70-betterlife-347d-libfprint.rules" "/lib/udev/rules.d/70-betterlife-347d-libfprint.rules" 2>/dev/null \
  || sudo install -Dm644 "${REPO_DIR}/udev/70-betterlife-347d-libfprint.rules" "/usr/lib/udev/rules.d/70-betterlife-347d-libfprint.rules"

sudo ldconfig
sudo systemd-hwdb update 2>/dev/null || sudo udevadm hwdb --update 2>/dev/null || true
sudo udevadm control --reload
sudo udevadm trigger --action=change --subsystem-match=usb --attr-match=idVendor=347d
sudo systemctl restart fprintd.service 2>/dev/null || true

echo ""
echo "==> Done! Detected fprintd devices:"
"${PREFIX}/bin/betterlife-fprintd" status || true
