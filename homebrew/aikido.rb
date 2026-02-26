# Install: brew install Bajuzjefe/tap/aikido
# Or: brew tap Bajuzjefe/tap && brew install aikido

class Aikido < Formula
  desc "Security analysis platform for Aiken smart contracts (Cardano)"
  homepage "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform"
  license "MIT"
  version "0.3.1"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.1/aikido-aarch64-apple-darwin.tar.gz"
      sha256 "30af9d78a8e5329ca67a395ce4471d53a15661b412f164fcdaf84b75f4826b1e"
    else
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.1/aikido-x86_64-apple-darwin.tar.gz"
      sha256 "51f9b0121cd2e2d1cd7dabf3c6419ec9321a48cdc6ec8160a6a5f842d1f682f5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.1/aikido-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "707ac59a38362ca13c849335a3cbac62445ed8082c1393311513c95b7fb8cd66"
    else
      url "https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform/releases/download/v0.3.1/aikido-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0ad5785bfd103187b60b4479afb5702f6c22d38631f775c8cea860c7201af67a"
    end
  end

  def install
    bin.install "aikido"
  end

  test do
    assert_match "aikido", shell_output("#{bin}/aikido --version")
  end
end
