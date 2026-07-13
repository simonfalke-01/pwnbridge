# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.4"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.4/pwnbridge_0.1.4_darwin_arm64.tar.gz"
    sha256 "5163ef958af30c880839db07720d86e22b5eb800d96f3ee87303429f5e395290"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.4/pwnbridge_0.1.4_darwin_amd64.tar.gz"
    sha256 "0fd4b5b3d42a0cf0425397fae841bef8e7ce4864eaf993746d4410ce54cc209e"
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
