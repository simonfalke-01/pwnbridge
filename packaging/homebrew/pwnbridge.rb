# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.6"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.6/pwnbridge_0.1.6_darwin_arm64.tar.gz"
    sha256 "828abefbc816770dd764b24448e2774249e986078e0758feea3aeb47470a34ac"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.6/pwnbridge_0.1.6_darwin_amd64.tar.gz"
    sha256 "1332d035f47579f808b15a8093baaf9563fc17d6c8db41def8ac6663e1aac05c"
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
