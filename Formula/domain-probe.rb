class DomainProbe < Formula
  desc "Fast, thorough domain intelligence from the terminal"
  homepage "https://github.com/stardevelin/domain-probe"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/stardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "fb9cd54f2d0737872a119a05473e94993179d8a8d9bc006252491b99a27753e1"
    end
    on_intel do
      url "https://github.com/stardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/stardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "683b1d238403eb84c59029d9beafdf5328a464c6e873f544c32c17fbb1cbca5a"
    end
    on_intel do
      url "https://github.com/stardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "953157d5439cb6f95ca6dab00ca5ecdee948952d4f7981b25dd958bb0dd9e961"
    end
  end

  def install
    bin.install "domain-probe"
  end

  test do
    assert_match "domain-probe", shell_output("#{bin}/domain-probe --help")
  end
end
