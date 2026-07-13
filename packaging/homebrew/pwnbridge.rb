# typed: strict
# frozen_string_literal: true

# Homebrew formula for the Darwin client and its Linux amd64 agent asset.
class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/simonfalke-01/pwnbridge"
  version "0.1.8"
  license "MIT"

  if Hardware::CPU.arm?
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.8/pwnbridge_0.1.8_darwin_arm64.tar.gz"
    sha256 "932c44b94e4cd7df7b549c8ec896a3981bac235c9c4e7a517bcbd4517b2d7434"
  else
    url "https://github.com/simonfalke-01/pwnbridge/releases/download/v0.1.8/pwnbridge_0.1.8_darwin_amd64.tar.gz"
    sha256 "1a4dd170b2dbc84d18eb9792d073c7d7f425c0788927bd60abd10457b19713af"
  end

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
    assert_match "pb COMMAND", shell_output("#{bin}/pb --help")
    assert_path_exists libexec/"pwnbridge/pwnbridge-agent-linux-amd64"
  end
end
