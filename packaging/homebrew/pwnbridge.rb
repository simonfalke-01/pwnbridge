# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.2"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.2/pwnbridge_0.1.2_darwin_arm64.tar.gz"
    sha256 "223e3948078d419aee9980cc3d490b283d289591d0be0659a95f41c04fd45f5d"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.2/pwnbridge_0.1.2_darwin_amd64.tar.gz"
    sha256 "ff57e1c37f355514af3b8d2e67ce9ab0c68e1c4affdb0366abed1a83eb47d518"
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
