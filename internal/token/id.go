package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Errorf("generate id: %w", err))
	}

	return hex.EncodeToString(buf)
}
