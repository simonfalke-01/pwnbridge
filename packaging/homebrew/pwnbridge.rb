# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.2.3"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.3/pwnbridge_0.2.3_darwin_arm64.tar.gz"
    sha256 "4b0f678868622ba602101f40b213405fd14ee4e6ac650274241ededfc3c02642"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.3/pwnbridge_0.2.3_darwin_amd64.tar.gz"
    sha256 "d2942beb840c5f75f52cfa2ccc3163cd6b56a34e193486feb8d3c06952866b7c"
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
