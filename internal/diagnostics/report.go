package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxDetailBytes      = 512
	maxRemediationBytes = 256
)

// Report is the common machine and human doctor result. Complete distinguishes
// a fully evaluated unhealthy environment from one where a collector could not
// finish.
type Report struct {
	OK       bool    `json:"ok"`
	Complete bool    `json:"complete"`
	Checks   []Check `json:"checks"`
}

func NewReport(checks []Check, complete bool) Report {
	normalized := make([]Check, len(checks))
	for index, check := range checks {
		check.Detail = singleLine(check.Detail, maxDetailBytes)
		check.Remediation = singleLine(check.Remediation, maxRemediationBytes)
		normalized[index] = check
	}
	return Report{OK: complete && Healthy(normalized), Complete: complete, Checks: normalized}
}

// Failure converts a probe error into a stable diagnostic check while keeping
// ordinary non-timeout errors useful and bounded by NewReport.
func Failure(name string, err error, remediation string, timeout time.Duration) Check {
	if err == nil {
		err = errors.New("diagnostic probe failed")
	}
	check := Check{Name: name, OK: false, Detail: err.Error(), Remediation: remediation, Severity: "error", State: "failed"}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		check.Detail = "timed out after " + timeout.String()
		check.State = "timeout"
	case errors.Is(err, context.Canceled):
		check.Detail = "cancelled"
		check.State = "cancelled"
	}
	return check
}

// Render writes one control-safe, line-oriented doctor report.
func Render(out io.Writer, report Report) error {
	return RenderStatus(out, report, "doctor")
}

// RenderStatus writes a report with a fixed caller-supplied operation label.
// Callers must not pass untrusted or user-controlled labels.
func RenderStatus(out io.Writer, report Report, label string) error {
	var buffer strings.Builder
	for _, check := range report.Checks {
		mark := "ok"
		if !check.OK {
			if check.Severity != "" && check.Severity != "error" {
				mark = "info"
			} else {
				mark = "FAIL"
			}
		}
		fmt.Fprintf(&buffer, "%-5s %-24s %s\n", mark, check.Name, check.Detail)
		if !check.OK && check.Remediation != "" {
			fmt.Fprintln(&buffer, "      fix:", check.Remediation)
		}
	}
	status := "ok"
	if !report.OK {
		status = "FAIL"
	}
	completeness := "complete"
	if !report.Complete {
		completeness = "incomplete"
	}
	fmt.Fprintf(&buffer, "%-5s %s (%s)\n", status, label, completeness)
	_, err := io.WriteString(out, buffer.String())
	return err
}

func singleLine(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "�")
	var cleaned strings.Builder
	for index := 0; index < len(value); {
		if value[index] == 0x1b {
			index = skipEscape(value, index+1)
			continue
		}
		r, size := utf8.DecodeRuneInString(value[index:])
		index += size
		switch {
		case unicode.IsSpace(r):
			cleaned.WriteByte(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			continue
		default:
			cleaned.WriteRune(r)
		}
	}
	result := strings.Join(strings.Fields(cleaned.String()), " ")
	if len(result) <= maximum {
		return result
	}
	const suffix = "…"
	limit := maximum - len(suffix)
	for limit > 0 && !utf8.RuneStart(result[limit]) {
		limit--
	}
	return result[:limit] + suffix
}

func skipEscape(value string, index int) int {
	if index >= len(value) {
		return index
	}
	switch value[index] {
	case '[':
		index++
		for index < len(value) {
			current := value[index]
			index++
			if current >= 0x40 && current <= 0x7e {
				break
			}
		}
	case ']':
		index++
		for index < len(value) {
			if value[index] == 0x07 {
				return index + 1
			}
			if value[index] == 0x1b && index+1 < len(value) && value[index+1] == '\\' {
				return index + 2
			}
			index++
		}
	default:
		index++
	}
	return index
}
