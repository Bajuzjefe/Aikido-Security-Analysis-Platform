# Feature #89: Homebrew formula — `brew install aikido`
# Install: brew install Bajuzjefe/tap/aikido
# Or: brew tap Bajuzjefe/tap && brew install aikido

class Aikido < Formula
  desc "Static analysis tool for Aiken smart contracts (Cardano)"
  homepage "https://github.com/Bajuzjefe/aikido"
  license "MIT"
  version "0.2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/aikido/releases/download/v0.2.0/aikido-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    else
      url "https://github.com/Bajuzjefe/aikido/releases/download/v0.2.0/aikido-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/aikido/releases/download/v0.2.0/aikido-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/Bajuzjefe/aikido/releases/download/v0.2.0/aikido-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_X64"
    end
  end

  def install
    bin.install "aikido"
  end

  test do
    assert_match "aikido", shell_output("#{bin}/aikido --version")
  end
end
