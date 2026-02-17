pkgname=domain-probe
pkgver=0.1.1
pkgrel=1
pkgdesc="Fast, thorough domain intelligence from the terminal"
arch=('x86_64')
url="https://github.com/dardevelin/domain-probe"
license=('MIT')
source=("https://github.com/dardevelin/domain-probe/releases/download/v${pkgver}/domain-probe-${pkgver}-x86_64-unknown-linux-gnu.tar.gz")
sha256sums=('004257e18f3b6123d0e515a1214ddc5582885a320ff6dfa04191021f6c8fdca7')

package() {
  install -Dm755 "$srcdir/domain-probe" "$pkgdir/usr/local/bin/domain-probe"
}
