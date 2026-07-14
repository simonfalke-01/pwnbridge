package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/simonfalke-01/pwnbridge/internal/agent"
	"github.com/simonfalke-01/pwnbridge/internal/protocol"
	"github.com/simonfalke-01/pwnbridge/internal/recovery"
	"github.com/simonfalke-01/pwnbridge/internal/transport"
)

const maxRemoteRecoveryControlBytes = 64 << 10

type boundedCapture struct {
	data  []byte
	limit int
}

func (w *boundedCapture) Write(data []byte) (int, error) {
	remaining := w.limit - len(w.data)
	if remaining > len(data) {
		remaining = len(data)
	}
	if remaining > 0 {
		w.data = append(w.data, data[:remaining]...)
	}
	return len(data), nil
}

func (w *boundedCapture) quoted() string {
	if len(w.data) == 0 {
		return ""
	}
	return strconv.QuoteToASCII(string(w.data))
}

func backupRemoteLoser(ctx context.Context, master *transport.Master, remoteRoot, relative, recoveryRoot, archive, backupID string) (recovery.Entry, error) {
	request, err := agent.EncodeRequest(protocol.RecoveryRequest{Root: remoteRoot, Path: relative})
	if err != nil {
		return recovery.Entry{}, err
	}
	operationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := master.Command(operationContext, false, "recovery-stream", request)
	return receiveRemoteLoser(ctx, cancel, command, relative, recoveryRoot, archive, backupID)
}

// receiveRemoteLoser owns the bidirectional stream transaction. Keeping the
// transport construction outside this function lets tests exercise the exact
// pipe and process lifecycle without requiring an SSH daemon.
func receiveRemoteLoser(ctx context.Context, cancel context.CancelFunc, command *exec.Cmd, relative, recoveryRoot, archive, backupID string) (recovery.Entry, error) {
	stdin, err := command.StdinPipe()
	if err != nil {
		return recovery.Entry{}, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return recovery.Entry{}, err
	}
	stderr := &boundedCapture{limit: maxRemoteRecoveryControlBytes}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return recovery.Entry{}, err
	}
	waitAfterFailure := func(operationErr error) (recovery.Entry, error) {
		cancel()
		_ = stdin.Close()
		waitErr := command.Wait()
		if ctx.Err() != nil {
			return recovery.Entry{}, ctx.Err()
		}
		if detail := stderr.quoted(); detail != "" {
			operationErr = errors.Join(operationErr, fmt.Errorf("remote recovery stderr: %s", detail))
		}
		if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
			operationErr = errors.Join(operationErr, waitErr)
		}
		return recovery.Entry{}, operationErr
	}
	reader := bufio.NewReaderSize(stdout, 32<<10)
	summary, err := recovery.ExtractArchive(reader, recoveryRoot, backupID)
	if err != nil {
		return waitAfterFailure(fmt.Errorf("extract remote recovery stream: %w", err))
	}
	entry, err := recovery.RecordSummary(recoveryRoot, archive, "local", relative, summary)
	if err != nil {
		_, operationErr := waitAfterFailure(fmt.Errorf("record remote recovery stream: %w", err))
		return recovery.Entry{}, fmt.Errorf("remote copy was preserved; complete local backup remains at %q but cataloging failed: %w", filepath.Join(recoveryRoot, backupID), operationErr)
	}
	if err := json.NewEncoder(stdin).Encode(protocol.RecoveryAck{Commit: true, SHA256: summary.SHA256}); err != nil {
		_, operationErr := waitAfterFailure(fmt.Errorf("acknowledge durable remote recovery: %w", err))
		return entry, fmt.Errorf("remote copy was preserved; durable backup is available at %q: %w", filepath.Join(recoveryRoot, backupID), operationErr)
	}
	if err := stdin.Close(); err != nil {
		_, operationErr := waitAfterFailure(fmt.Errorf("close remote recovery acknowledgement: %w", err))
		return entry, fmt.Errorf("remote loser outcome is uncertain after durable backup %q: %w", filepath.Join(recoveryRoot, backupID), operationErr)
	}
	control, readErr := io.ReadAll(io.LimitReader(reader, maxRemoteRecoveryControlBytes+1))
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return entry, fmt.Errorf("remote loser outcome is uncertain after durable backup %q: %w", filepath.Join(recoveryRoot, backupID), ctx.Err())
	}
	if len(control) > maxRemoteRecoveryControlBytes {
		readErr = errors.New("remote recovery result exceeds its size limit")
	}
	if waitErr != nil || readErr != nil {
		detail := stderr.quoted()
		return entry, fmt.Errorf("remote loser outcome is uncertain after durable backup %q: %w%s", filepath.Join(recoveryRoot, backupID), errors.Join(waitErr, readErr), formatRecoveryStderr(detail))
	}
	var result protocol.RecoveryResult
	if err := decodeRemoteRecoveryResult(control, summary, &result); err != nil {
		return entry, fmt.Errorf("remote loser outcome is uncertain after durable backup %q: %w", filepath.Join(recoveryRoot, backupID), err)
	}
	return entry, nil
}

func decodeRemoteRecoveryResult(data []byte, summary recovery.ArchiveSummary, result *protocol.RecoveryResult) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode remote recovery result: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("remote recovery result contains trailing data")
	}
	if !result.Removed || result.SHA256 != summary.SHA256 || result.Size != summary.Size || result.Items != summary.Items {
		return errors.New("remote recovery result does not match the durable backup")
	}
	return nil
}

func formatRecoveryStderr(detail string) string {
	if detail == "" {
		return ""
	}
	return "; remote stderr=" + detail
}
