package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Message{Protocol: 1, Type: "ping", Token: "secret"}
	var buffer bytes.Buffer
	if err := Encode(&buffer, want); err != nil {
		t.Fatal(err)
	}
	var got Message
	if err := Decode(&buffer, &got); err != nil {
		t.Fatal(err)
	}
	if got.Protocol != want.Protocol || got.Type != want.Type || got.Token != want.Token {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestFrameLimit(t *testing.T) {
	var b bytes.Buffer
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], MaxFrame+1)
	b.Write(size[:])
	var got Message
	if err := Decode(&b, &got); err == nil {
		t.Fatal("expected limit error")
	}
}

func TestConsecutiveFramesDoNotLoseBufferedBytes(t *testing.T) {
	var stream bytes.Buffer
	if err := Encode(&stream, Message{Protocol: 1, Type: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := Encode(&stream, Message{Protocol: 1, Type: "two"}); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"one", "two"} {
		var message Message
		if err := Decode(&stream, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type != wanted {
			t.Fatalf("got %q want %q", message.Type, wanted)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		_ = Decode(bytes.NewReader(data), &value)
	})
}
