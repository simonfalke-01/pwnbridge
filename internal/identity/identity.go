package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func Random(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random identity: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
