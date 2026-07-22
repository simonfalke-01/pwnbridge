package version

import (
	"strings"
	"testing"
)

func TestCheckToolchainRejectsCVE202639822(t *testing.T) {
	for _, value := range []string{
		"go1.26", "go1.26rc1", "go1.26.0", "go1.26.3", "go1.26.4",
		"go1.27", "go1.27beta1", "go1.27rc1",
	} {
		t.Run(value, func(t *testing.T) {
			err := CheckToolchain(value)
			if err == nil || !strings.Contains(err.Error(), "CVE-2026-39822") {
				t.Fatalf("CheckToolchain(%q) = %v", value, err)
			}
		})
	}
}

func TestCheckToolchainAcceptsFixedReleases(t *testing.T) {
	for _, value := range []string{
		"go1.25.12", "go1.25.13", "go1.26.5", "go1.26.6",
		"go1.27rc2", "go1.27.0", "go1.28",
		"devel go1.28-deadbeef",
	} {
		t.Run(value, func(t *testing.T) {
			if err := CheckToolchain(value); err != nil {
				t.Fatalf("CheckToolchain(%q) = %v", value, err)
			}
		})
	}
}
