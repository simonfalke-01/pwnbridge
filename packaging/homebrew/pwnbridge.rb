# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.13"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.13/pwnbridge_0.1.13_darwin_arm64.tar.gz"
    sha256 "9a3754e14c6af070996522ea7a7ba78a17bfe24fb54d706a3749fbcff3de8e2a"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.13/pwnbridge_0.1.13_darwin_amd64.tar.gz"
    sha256 "bcc808cd94eb1043ae78f5b917411aec21bafdf4d5606dca2057a8c0a3dc2372"
  end

  depends_on "mosh"
  depends_on "mutagen-io/mutagen/mutagen"

  def install
    bin.install "pwnbridge"
    bin.install_symlink "pwnbridge" => "pb"
    (libexec/"pwnbridge").install "pwnbridge-agent-linux-amd64"
    bash_completion.install "completions/pwnbridge.bash" => "pwnbridge"
    zsh_completion.install "completions/_pwnbridge"
    fish_completion.install "completions/pwnbridge.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pwnbridge version")
    assert_match version.to_s, shell_output("#{bin}/pwnbridge --version")
    assert_match "pb COMMAND", shell_output("#{bin}/pb --help")
    assert_path_exists libexec/"pwnbridge/pwnbridge-agent-linux-amd64"
  end
end
