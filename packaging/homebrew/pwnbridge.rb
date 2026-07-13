# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.12"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.12/pwnbridge_0.1.12_darwin_arm64.tar.gz"
    sha256 "28e3cca49b6f7feab2ca2e5f3a97aa92eb4d818b6b5a67be22550ee30d27d3ff"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.12/pwnbridge_0.1.12_darwin_amd64.tar.gz"
    sha256 "7e33bb70fde8c8247c5c4d18b222cad5decf2c18246685b53a7021c432daac87"
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
