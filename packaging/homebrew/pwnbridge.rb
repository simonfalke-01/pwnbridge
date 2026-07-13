# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.3"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.3/pwnbridge_0.1.3_darwin_arm64.tar.gz"
    sha256 "a3b0f915d2a7004aaee9407f0ed4a2341fbb02e1966fe7067588e1e8a74afe9c"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.3/pwnbridge_0.1.3_darwin_amd64.tar.gz"
    sha256 "d6cb72f8b7b75a9d8fdad10d423cb86c7b32b6644cc149a9c98a14a9c2d58809"
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
