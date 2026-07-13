# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.0"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.0/pwnbridge_0.1.0_darwin_arm64.tar.gz"
    sha256 "6157e679e618711bd4b97c58697c84d9117825d7020dd599662354811b103f60"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.0/pwnbridge_0.1.0_darwin_amd64.tar.gz"
    sha256 "e1beb95fc139f542a0395817768ba0920ea7ffc81fe1302412fa939a251f7e65"
  end

  depends_on "mutagen-io/mutagen/mutagen"

  def install
    bin.install "pwnbridge"
    (libexec/"pwnbridge").install "pwnbridge-agent-linux-amd64"
    bash_completion.install "completions/pwnbridge.bash" => "pwnbridge"
    zsh_completion.install "completions/_pwnbridge"
    fish_completion.install "completions/pwnbridge.fish"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pwnbridge version")
    assert_path_exists libexec/"pwnbridge/pwnbridge-agent-linux-amd64"
  end
end
