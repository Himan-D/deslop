class Deslop < Formula
  desc "Codebase Inversion & Architectural De-slopping Engine in Rust"
  homepage "https://github.com/Himan-D/deslop"
  version "0.1.0"
  license "MIT OR Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-aarch64-apple-darwin.tar.gz"
      # REPLACE_WITH_SHA256_AARCH64_APPLE_DARWIN (updated by release automation)
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    on_intel do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-x86_64-apple-darwin.tar.gz"
      # REPLACE_WITH_SHA256_X86_64_APPLE_DARWIN (updated by release automation)
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-aarch64-unknown-linux-gnu.tar.gz"
      # REPLACE_WITH_SHA256_AARCH64_UNKNOWN_LINUX_GNU (updated by release automation)
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    on_intel do
      url "https://github.com/Himan-D/deslop/releases/download/v#{version}/deslop-x86_64-unknown-linux-gnu.tar.gz"
      # REPLACE_WITH_SHA256_X86_64_UNKNOWN_LINUX_GNU (updated by release automation)
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "deslop"
  end

  test do
    system "#{bin}/deslop", "--version"
  end
end
