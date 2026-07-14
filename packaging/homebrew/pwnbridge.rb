# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.2.1"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.1/pwnbridge_0.2.1_darwin_arm64.tar.gz"
    sha256 "e6ce43e0581d5eb362f8aa229c89ec2af45dec86c98150ea2c4161d47512e5a2"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.1/pwnbridge_0.2.1_darwin_amd64.tar.gz"
    sha256 "99d6c959a87fc0d56d3bab819e149fca8b169f4513431e54d1b2aa7f82396eb1"
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
