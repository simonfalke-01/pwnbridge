# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.5"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.5/pwnbridge_0.1.5_darwin_arm64.tar.gz"
    sha256 "bbb982f4a1255ad3d8d9856cd131a3d42f2be01003aa8911e64d1e41612dc81f"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.5/pwnbridge_0.1.5_darwin_amd64.tar.gz"
    sha256 "ca1181111674925fc17ea38801c1b0e1336d3b36304861d64273013d2fef44d1"
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
