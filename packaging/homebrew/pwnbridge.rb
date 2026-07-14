# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.2.0"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.0/pwnbridge_0.2.0_darwin_arm64.tar.gz"
    sha256 "2531221a1cb04bfc66d99da2b34969de021d97a547bb6bd52d2d2a6caf32fc1d"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.2.0/pwnbridge_0.2.0_darwin_amd64.tar.gz"
    sha256 "ab2b238c684162e27db27b6dfd5f13a4dba26a9eeffe5d4fe0b6191c37ec27d3"
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
