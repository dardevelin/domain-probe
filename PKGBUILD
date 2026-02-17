pkgname=domain-probe
pkgver=0.1.0
pkgrel=1
pkgdesc="Fast, thorough domain intelligence from the terminal"
arch=('x86_64')
url="https://github.com/stardevelin/domain-probe"
license=('MIT')
source=("https://github.com/stardevelin/domain-probe/releases/download/v${pkgver}/domain-probe-${pkgver}-x86_64-unknown-linux-gnu.tar.gz")
sha256sums=('953157d5439cb6f95ca6dab00ca5ecdee948952d4f7981b25dd958bb0dd9e961')

package() {
  install -Dm755 "$srcdir/domain-probe" "$pkgdir/usr/local/bin/domain-probe"
}
