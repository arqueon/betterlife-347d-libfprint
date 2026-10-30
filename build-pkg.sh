#!/usr/bin/env bash
# Builds the unified 3-family Arch package (libfprint-cs9711-zk9500-betterlife-git)
# inside /tmp so the working tree stays clean. Automatically clones zk9500-libfprint
# if ../zk9500-libfprint is not present locally.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${BETTERLIFE_BUILDDIR:-/tmp/pkgbuild-betterlife}"
ZK9500_DIR="${ZK9500_DIR:-${PROJECT_DIR}/../zk9500-libfprint}"

echo "==> Preparing clean build directory in ${WORK_DIR}..."
mkdir -p "${WORK_DIR}"
rm -f "${WORK_DIR}"/libfprint-cs9711-zk9500-betterlife-git-*.pkg.tar.*

if [[ ! -f "${ZK9500_DIR}/drivers/zk9500.c" ]]; then
  ZK9500_DIR="${WORK_DIR}/zk9500-libfprint-src"
  if [[ ! -d "${ZK9500_DIR}/.git" ]]; then
    git clone --depth 1 https://github.com/arqueon/zk9500-libfprint.git "${ZK9500_DIR}"
  fi
fi

install -m644 "${PROJECT_DIR}/PKGBUILD" "${WORK_DIR}/PKGBUILD"
for _f in betterlife347d_moc.c betterlife347d.c betterlife347d-proto.c betterlife347d-proto.h sm3.c sm3.h sm4.c sm4.h; do
  install -m644 "${PROJECT_DIR}/drivers/betterlife347d/${_f}" "${WORK_DIR}/${_f}"
done
install -m644 "${ZK9500_DIR}/drivers/zk9500.c" "${WORK_DIR}/zk9500.c"
install -m644 "${PROJECT_DIR}/tools/betterlife347d-probe.c" "${WORK_DIR}/betterlife347d-probe.c"
install -m644 "${ZK9500_DIR}/tools/zk9500-probe.c" "${WORK_DIR}/zk9500-probe.c"
install -m755 "${PROJECT_DIR}/tools/fprintd-multi" "${WORK_DIR}/fprintd-multi"
install -m644 "${PROJECT_DIR}/patches/0001-unified-cs9711-zk9500-betterlife347d.patch" \
  "${WORK_DIR}/0001-unified-cs9711-zk9500-betterlife347d.patch"
install -m644 "${PROJECT_DIR}/udev/70-fprint-multi-readers.rules" \
  "${WORK_DIR}/70-fprint-multi-readers.rules"

cd "${WORK_DIR}"
echo "==> Running makepkg -sfc..."
makepkg -sfc --noconfirm

PKG_FILE="$(ls -1t "${WORK_DIR}"/libfprint-cs9711-zk9500-betterlife-git-[0-9]*.pkg.tar.* | grep -v '\-debug-' | head -n1)"
echo ""
echo "==> Unified package built successfully:"
ls -lh "${PKG_FILE}"
