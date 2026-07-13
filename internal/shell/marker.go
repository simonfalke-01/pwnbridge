package shell

import (
	"bytes"
	"strconv"
)

type Event struct {
	Data   []byte
	Prompt bool
	Status int
}

type MarkerParser struct {
	prefix  []byte
	pending []byte
}

func NewMarkerParser(nonce string) *MarkerParser {
	return &MarkerParser{prefix: []byte("\x1b]777;pwnbridge;" + nonce + ";prompt;")}
}

func (p *MarkerParser) Feed(data []byte) []Event {
	p.pending = append(p.pending, data...)
	var events []Event
	for {
		index := bytes.Index(p.pending, p.prefix)
		if index < 0 {
			keep := suffixPrefix(p.pending, p.prefix)
			emit := len(p.pending) - keep
			if emit > 0 {
				events = appendData(events, p.pending[:emit])
				p.pending = append([]byte(nil), p.pending[emit:]...)
			}
			break
		}
		if index > 0 {
			events = appendData(events, p.pending[:index])
			p.pending = p.pending[index:]
		}
		end := bytes.IndexByte(p.pending[len(p.prefix):], '\a')
		if end < 0 {
			break
		}
		end += len(p.prefix)
		status, err := strconv.Atoi(string(p.pending[len(p.prefix):end]))
		if err != nil {
			events = appendData(events, p.pending[:1])
			p.pending = p.pending[1:]
			continue
		}
		events = append(events, Event{Prompt: true, Status: status})
		p.pending = p.pending[end+1:]
	}
	return events
}

func (p *MarkerParser) Flush() []byte {
	data := append([]byte(nil), p.pending...)
	p.pending = nil
	return data
}

func suffixPrefix(data, prefix []byte) int {
	limit := len(prefix) - 1
	if len(data) < limit {
		limit = len(data)
	}
	for size := limit; size > 0; size-- {
		if bytes.Equal(data[len(data)-size:], prefix[:size]) {
			return size
		}
	}
	return 0
}

func appendData(events []Event, data []byte) []Event {
	if len(data) == 0 {
		return events
	}
	copyData := append([]byte(nil), data...)
	if len(events) > 0 && !events[len(events)-1].Prompt {
		events[len(events)-1].Data = append(events[len(events)-1].Data, copyData...)
		return events
	}
	return append(events, Event{Data: copyData})
}
