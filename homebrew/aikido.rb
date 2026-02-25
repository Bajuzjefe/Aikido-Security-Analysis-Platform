# Feature #89: Homebrew formula — `brew install aikido`
# Install: brew install Bajuzjefe/tap/aikido
# Or: brew tap Bajuzjefe/tap && brew install aikido

class Aikido < Formula
  desc "Static analysis tool for Aiken smart contracts (Cardano)"
  homepage "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
  license "MIT"
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.0/aikido-aarch64-apple-darwin.tar.gz"
      sha256 "584b7dcfa93c13801330e6951202348b33adfc215197fd68429e903be5107901"
    else
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.0/aikido-x86_64-apple-darwin.tar.gz"
      sha256 "7bcf79c22d39ffb95e8dd802fc91f1e0305654f80bbae6bb63da28faa8710657"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.0/aikido-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5c61c2f87c179e777397594eea9beae9ff42708903b2b45874549d8370d1b2e1"
    else
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.0/aikido-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "fa8e103dc41c600b97a3a58a229108658cd940f336c68be1afe82c3272caba32"
    end
  end

  def install
    bin.install "aikido"
  end

  test do
    assert_match "aikido", shell_output("#{bin}/aikido --version")
  end
end
