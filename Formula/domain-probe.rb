class DomainProbe < Formula
  desc "Fast, thorough domain intelligence from the terminal"
  homepage "https://github.com/dardevelin/domain-probe"
  version "0.1.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.1/domain-probe-0.1.1-aarch64-apple-darwin.tar.gz"
      sha256 "b5b2e9b233e838c20d1dc483c3bf47d263b7f9f6f232900223493ff80d4b0755"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.1/domain-probe-0.1.1-x86_64-apple-darwin.tar.gz"
      sha256 "d6b8a50444f7be2dc6ec45ce18aff09d00ad0d2957e975b0fb6c58fecf592094"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.1/domain-probe-0.1.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "566ce842d96fbf3190d7204b7465fbcbfbc4fec1b317cb9512eb46730194ecda"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.1/domain-probe-0.1.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "004257e18f3b6123d0e515a1214ddc5582885a320ff6dfa04191021f6c8fdca7"
    end
  end

  def install
    bin.install "domain-probe"
  end

  test do
    assert_match "domain-probe", shell_output("#{bin}/domain-probe --help")
  end
end
