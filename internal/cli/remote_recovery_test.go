package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
)

func TestReceiveRemoteLoserCompletesSubprocessTransaction(t *testing.T) {
	source := t.TempDir()
	recoveryRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "loser"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "loser", "artifact"), []byte("remote evidence"), 0o640); err != nil {
		t.Fatal(err)
	}
	request, err := agent.EncodeRequest(protocol.RecoveryRequest{Root: source, Path: "loser"})
	if err != nil {
		t.Fatal(err)
	}
	archive := recovery.ArchiveName(time.Date(2026, 7, 14, 13, 0, 0, 0, time.UTC))
	backupID, err := recovery.BackupID(archive, "local", "loser")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestRemoteRecoveryHelperProcess", "--", request)
	command.Env = append(os.Environ(), "PWNBRIDGE_RECOVERY_HELPER=1")
	entry, err := receiveRemoteLoser(ctx, cancel, command, "loser", recoveryRoot, archive, backupID)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != backupID || entry.SHA256 == "" || entry.Kind != "directory" || entry.Items != 2 {
		t.Fatalf("entry = %#v", entry)
	}
	if _, err := os.Lstat(filepath.Join(source, "loser")); !os.IsNotExist(err) {
		t.Fatalf("acknowledged remote loser remains: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(recoveryRoot, backupID, "artifact"))
	if err != nil || string(data) != "remote evidence" {
		t.Fatalf("durable backup = %q, %v", data, err)
	}
	entries, err := recovery.List(recoveryRoot)
	if err != nil || len(entries) != 1 || entries[0].SHA256 != entry.SHA256 {
		t.Fatalf("inventory = %#v, %v", entries, err)
	}
}

func TestRemoteRecoveryHelperProcess(t *testing.T) {
	if os.Getenv("PWNBRIDGE_RECOVERY_HELPER") != "1" {
		return
	}
	request := os.Args[len(os.Args)-1]
	if err := agent.Main([]string{"recovery-stream", request}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestDecodeRemoteRecoveryResultIsStrict(t *testing.T) {
	summary := recovery.ArchiveSummary{SHA256: strings.Repeat("a", 64), Size: 9, Items: 2}
	valid, err := json.Marshal(protocol.RecoveryResult{SHA256: summary.SHA256, Size: summary.Size, Items: summary.Items, Removed: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "valid", data: string(valid)},
		{name: "unknown", data: strings.TrimSuffix(string(valid), "}") + `,"extra":true}`},
		{name: "trailing", data: string(valid) + `{}`},
		{name: "not-removed", data: `{"sha256":"` + summary.SHA256 + `","size":9,"items":2,"removed":false}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result protocol.RecoveryResult
			err := decodeRemoteRecoveryResult([]byte(test.data), summary, &result)
			if test.name == "valid" && err != nil {
				t.Fatal(err)
			}
			if test.name != "valid" && err == nil {
				t.Fatal("invalid recovery result was accepted")
			}
		})
	}
}

func TestBoundedRecoveryStderrCapture(t *testing.T) {
	capture := &boundedCapture{limit: 4}
	if n, err := capture.Write([]byte("ab\x1b[2J")); err != nil || n != 6 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if capture.quoted() != `"ab\x1b["` {
		t.Fatalf("quoted capture = %s", capture.quoted())
	}
}
