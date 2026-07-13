package shell

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMarkerEverySplit(t *testing.T) {
	marker := []byte("before\x1b]777;pwnbridge;0123456789abcdef;prompt;7\aafter")
	for split := 0; split <= len(marker); split++ {
		parser := NewMarkerParser("0123456789abcdef")
		events := append(parser.Feed(marker[:split]), parser.Feed(marker[split:])...)
		var data []byte
		prompts := 0
		status := 0
		for _, event := range events {
			if event.Prompt {
				prompts++
				status = event.Status
			} else {
				data = append(data, event.Data...)
			}
		}
		data = append(data, parser.Flush()...)
		if string(data) != "beforeafter" || prompts != 1 || status != 7 {
			t.Fatalf("split %d: data=%q prompts=%d status=%d events=%#v", split, data, prompts, status, events)
		}
	}
}

func TestFakeMarkerPreserved(t *testing.T) {
	p := NewMarkerParser("realnonce")
	input := []byte("x\x1b]777;pwnbridge;wrong;prompt;0\ay")
	var output []byte
	for _, e := range p.Feed(input) {
		output = append(output, e.Data...)
	}
	output = append(output, p.Flush()...)
	if !bytes.Equal(input, output) {
		t.Fatalf("got %q", output)
	}
}

func FuzzMarker(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("\x1b]777;pwnbridge;nonce123;prompt;0\a"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewMarkerParser("nonce123")
		for i := range data {
			_ = p.Feed(data[i : i+1])
		}
		_ = p.Flush()
		_ = fmt.Sprint(len(data))
	})
}
