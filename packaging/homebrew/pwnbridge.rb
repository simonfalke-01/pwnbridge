class Pwnbridge < Formula
  desc "Make a remote Linux x86-64 pwn environment feel local on macOS"
  homepage "https://github.com/pwnbridge/pwnbridge"
  license "MIT"
  head "https://github.com/pwnbridge/pwnbridge.git", branch: "main"

  depends_on "go" => :build
  depends_on "mutagen-io/mutagen/mutagen"

  def install
    ldflags = %W[
      -s -w
      -X github.com/pwnbridge/pwnbridge/internal/version.Version=#{version}
    ]
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/pwnbridge"
    system({"CGO_ENABLED" => "0", "GOOS" => "linux", "GOARCH" => "amd64"},
           "go", "build", "-trimpath", "-o", "pwnbridge-agent-linux-amd64", "./cmd/pwnbridge-agent")
    (libexec/"pwnbridge").install "pwnbridge-agent-linux-amd64"
    generate_completions_from_executable(bin/"pwnbridge", "completion")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pwnbridge version")
    assert_predicate libexec/"pwnbridge/pwnbridge-agent-linux-amd64", :exist?
  end
end
