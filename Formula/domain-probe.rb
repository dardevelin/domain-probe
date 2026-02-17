class DomainProbe < Formula
  desc "Fast, thorough domain intelligence from the terminal"
  homepage "https://github.com/dardevelin/domain-probe"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "3fc7f913c24b5522c04e007214214d1d6a171ecd7b983f38b766534ced0846bc"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "c5ab2872e934bf75d4c483082b5d6faf24cc5b0c684aaa0ffacded742814fd94"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "683b1d238403eb84c59029d9beafdf5328a464c6e873f544c32c17fbb1cbca5a"
    end
    on_intel do
      url "https://github.com/dardevelin/domain-probe/releases/download/v0.1.0/domain-probe-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
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
