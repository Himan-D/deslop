class Deslop < Formula
  desc "Deterministic CI & MCP architectural and SAST gate against AI-generated slop, dependency cycles, and dead code"
  homepage "https://github.com/Himan-D/deslop"
  version "0.1.1"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-aarch64-apple-darwin.tar.gz"
      sha256 "b4d36ec605bd790bde9c219cfc775e2c6dee8c6de96f14de2f18ebd86d00eff3"
    end

    on_intel do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-x86_64-apple-darwin.tar.gz"
      sha256 "143a87c60b99184607d24020b7f85a9688a0de9e15e80f926b26145c534cf045"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e8e6d1a917d4b08aa08b82ec7991eeeef352c2544efe950dea70f569ed757225"
    end

    on_intel do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bafecceeb09a9135392087fa99e60d2d5dc4792ce4b90e6d14c8e58bcd4e27f6"
    end
  end

  def install
    bin.install "deslop"
  end

  test do
    system "#{bin}/deslop", "--version"
  end
end
