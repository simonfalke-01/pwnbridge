package version

import (
	"fmt"
	goversion "go/version"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

const (
	GlobalConfigSchema  = 2
	ProjectConfigSchema = 1
	// ConfigSchema is retained for version output and means the global schema.
	ConfigSchema     = GlobalConfigSchema
	ProtocolVersion  = 4
	ProviderProtocol = 1
	MutagenVersion   = "0.18.1"
)

var cve202639822Ranges = [...]struct {
	introduced string
	fixed      string
}{
	{introduced: "go1.26", fixed: "go1.26.5"},
	{introduced: "go1.27", fixed: "go1.27rc2"},
}

// CheckRuntimeToolchain refuses binaries whose standard library has the
// os.Root escape fixed by CVE-2026-39822. go.mod enforces the safe Go 1.25.12
// floor, but module version selection cannot exclude later 1.26 patch releases.
func CheckRuntimeToolchain() error {
	return CheckToolchain(runtime.Version())
}

func CheckToolchain(value string) error {
	if !goversion.IsValid(value) {
		return nil
	}
	for _, affected := range cve202639822Ranges {
		if goversion.Compare(value, affected.introduced) >= 0 && goversion.Compare(value, affected.fixed) < 0 {
			return fmt.Errorf("Go toolchain %s is unsafe for pwnbridge: CVE-2026-39822 can escape os.Root boundaries; rebuild with Go 1.25.12, Go 1.26.5, or a fixed later release", value)
		}
	}
	return nil
}
