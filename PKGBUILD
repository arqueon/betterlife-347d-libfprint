# Maintainer: arqueon <66568719+arqueon@users.noreply.github.com>
pkgname=libfprint-cs9711-zk9500-betterlife-git
pkgver=1.94.10+1.r1866.20260217.02b285c
pkgrel=5
pkgdesc="libfprint-2 with Blestech Betterlife (347d:0302 MOC & 347d:0304 MOH), ZKTeco ZK9500 (1b55:0124), and Chipsailing CS9711 (2541:0236) support (OpenCV 4/5)"
arch=('x86_64' 'aarch64')
url="https://github.com/arqueon/betterlife-347d-libfprint"
license=('LGPL-2.1-or-later')
groups=('fprint')
depends=(
  'glib2'
  'glibc'
  'libgcc'
  'libgudev'
  'libgusb'
  'libusb'
  'opencv'
  'openssl'
  'pixman'
)
optdepends=(
  'fprintd: D-Bus daemon and PAM module for fingerprint authentication'
  'python-gobject: for fprintd-multi / betterlife-fprintd / zk9500-fprintd CLI'
)
makedepends=(
  'cmake'
  'git'
  'glib2-devel'
  'meson'
  'ninja'
  'pkgconf'
)
provides=(
  "libfprint=${pkgver}"
  'libfprint-2.so'
  'libfprint-cs9711'
  'libfprint-zk9500'
  'libfprint-betterlife-347d'
)
conflicts=(
  'libfprint'
  'libfprint-cs9711-rebase-git'
  'libfprint-cs9711-zk9500-git'
  'libfprint-zk9500-git'
  'libfprint-betterlife-347d-git'
)
replaces=(
  'libfprint-cs9711-rebase-git'
  'libfprint-cs9711-zk9500-git'
)
source=(
  'libfprint-CS9711::git+https://github.com/archeYR/libfprint-CS9711.git#branch=cs9711-rebase'
  'betterlife347d_moc.c'
  'betterlife347d.c'
  'betterlife347d-proto.c'
  'betterlife347d-proto.h'
  'sm3.c'
  'sm3.h'
  'sm4.c'
  'sm4.h'
  'zk9500.c'
  'betterlife347d-probe.c'
  'zk9500-probe.c'
  'fprintd-multi'
  '0001-unified-cs9711-zk9500-betterlife347d.patch'
  '70-fprint-multi-readers.rules'
)
sha256sums=(
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
  'SKIP'
)

pkgver() {
  cd "${srcdir}/libfprint-CS9711"
  local _base _rev _date _hash
  _base="$(meson introspect --projectinfo meson.build 2>/dev/null | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')"
  [[ -z "${_base}" ]] && _base="1.94.10"
  _rev="$(git rev-list --count HEAD)"
  _date="$(git log -1 --format=%cd --date=format:%Y%m%d)"
  _hash="$(git rev-parse --short=7 HEAD)"
  printf '%s+1.r%s.%s.%s' "${_base}" "${_rev}" "${_date}" "${_hash}"
}

prepare() {
  cd "${srcdir}/libfprint-CS9711"
  git checkout -- .
  patch -Np1 -i "${srcdir}/0001-unified-cs9711-zk9500-betterlife347d.patch"

  install -Dm644 "${srcdir}/zk9500.c" "libfprint/drivers/zk9500.c"
  for _f in betterlife347d_moc.c betterlife347d.c betterlife347d-proto.c betterlife347d-proto.h sm3.c sm3.h sm4.c sm4.h; do
    install -Dm644 "${srcdir}/${_f}" "libfprint/drivers/betterlife347d/${_f}"
  done
}

build() {
  local _gir_opt="-Dintrospection=false"
  if [[ -x /usr/bin/g-ir-scanner ]]; then
    _gir_opt="-Dintrospection=true"
  fi

  arch-meson "${srcdir}/libfprint-CS9711" build \
    "${_gir_opt}" \
    -Dudev_hwdb=enabled \
    -Dinstalled-tests=false \
    -Ddoc=false \
    -Dgtk-examples=false

  meson compile -C build

  # Compile standalone safe USB diagnostic tools
  # shellcheck disable=SC2046,SC2086
  cc ${CFLAGS} ${CPPFLAGS} -O2 -Wall -Wextra -I"${srcdir}" \
    "${srcdir}/betterlife347d-probe.c" \
    "${srcdir}/betterlife347d-proto.c" \
    "${srcdir}/sm3.c" \
    "${srcdir}/sm4.c" \
    -o "${srcdir}/betterlife347d-probe" \
    $(pkg-config --cflags --libs glib-2.0 libusb-1.0 openssl) ${LDFLAGS}

  # shellcheck disable=SC2046,SC2086
  cc ${CFLAGS} ${CPPFLAGS} -O2 -Wall -Wextra \
    "${srcdir}/zk9500-probe.c" -o "${srcdir}/zk9500-probe" \
    $(pkg-config --cflags --libs libusb-1.0) ${LDFLAGS}
}

check() {
  meson test -C build --suite unit-tests --print-errorlogs
  ./build/libfprint/fprint-list-supported-devices | grep -q "347d:0302"
  ./build/libfprint/fprint-list-supported-devices | grep -q "347d:0304"
  ./build/libfprint/fprint-list-supported-devices | grep -q "1b55:0124"
  ./build/libfprint/fprint-list-supported-devices | grep -q "2541:0236"
}

package() {
  meson install -C build --destdir "${pkgdir}"

  install -Dm755 "${srcdir}/betterlife347d-probe" \
    "${pkgdir}/usr/bin/betterlife347d-probe"
  install -Dm755 "${srcdir}/zk9500-probe" \
    "${pkgdir}/usr/bin/zk9500-probe"
  install -Dm755 "${srcdir}/fprintd-multi" \
    "${pkgdir}/usr/bin/fprintd-multi"

  ln -s fprintd-multi "${pkgdir}/usr/bin/betterlife-fprintd"
  ln -s fprintd-multi "${pkgdir}/usr/bin/zk9500-fprintd"

  install -Dm644 "${srcdir}/70-fprint-multi-readers.rules" \
    "${pkgdir}/usr/lib/udev/rules.d/70-fprint-multi-readers.rules"
}
