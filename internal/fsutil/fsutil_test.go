package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadJSONLimitAndStrictFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "value.json")
	type value struct {
		Name string `json:"name"`
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got value
	if err := ReadJSONLimit(path, 64, &got); err != nil || got.Name != "ok" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("unknown field was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"name":"ok"}{"name":"second"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"name":"`+strings.Repeat("x", 100)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONLimit(path, 64, &got); err == nil {
		t.Fatal("oversized JSON was accepted")
	}
}
