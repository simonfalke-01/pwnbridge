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

func TestFrameRejectsUnknownFields(t *testing.T) {
	data := []byte(`{"protocol":1,"type":"ping","unknown":true}`)
	var frame bytes.Buffer
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	frame.Write(size[:])
	frame.Write(data)
	var message Message
	if err := Decode(&frame, &message); err == nil {
		t.Fatal("protocol frame accepted an unknown field")
	}
}

func TestPayloadRejectsUnknownFields(t *testing.T) {
	message := Message{Payload: []byte(`{"title":"debug","unknown":true}`)}
	if _, err := ParsePayload[OpenPayload](message); err == nil {
		t.Fatal("protocol payload accepted an unknown field")
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

func BenchmarkDecodeMessage(b *testing.B) {
	var frame bytes.Buffer
	if err := Encode(&frame, Message{Protocol: 1, Type: "open", SessionID: "0123456789abcdef", RequestID: "abcdef0123456789", Token: "0123456789abcdef0123456789abcdef", Payload: Payload(OpenPayload{Title: "pwntools GDB"})}); err != nil {
		b.Fatal(err)
	}
	data := bytes.Clone(frame.Bytes())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		var message Message
		if err := Decode(bytes.NewReader(data), &message); err != nil {
			b.Fatal(err)
		}
	}
}
