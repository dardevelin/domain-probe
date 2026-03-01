class DomainProbe < Formula
  desc "Fast, thorough domain intelligence from the terminal"
  homepage "https://github.com/dardevelin/domain-probe"
  version "0.1.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.2/domain-probe-0.1.2-aarch64-apple-darwin.tar.gz"
      sha256 "e403a900521ad98e27b49523f832333349d89a1dca8ba91dce36ecaf44ebb9e9"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.2/domain-probe-0.1.2-x86_64-apple-darwin.tar.gz"
      sha256 "d2435ad3e987965a57ca303978ee151aada22cc9dc6d09e676161b4e5741d1fb"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.2/domain-probe-0.1.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "888d55b7ddf02221da455a4a42cc664bd741ac598fa71baa80e0afc8b3ca92d5"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.2/domain-probe-0.1.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "e3b6f310934cfbb0d8ae81af3d97ea627831c7cdc9bbc114a74c5c00be292a85"
    end
  end

  def install
    bin.install "domain-probe"
  end

  test do
    assert_match "domain-probe", shell_output("#{bin}/domain-probe --help")
  end
end
