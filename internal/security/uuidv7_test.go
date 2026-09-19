package security

import (
	"regexp"
	"testing"
)

func TestUUIDv7FormatAndUniqueness(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]bool)
	for range 1000 {
		id, err := NewUUIDv7()
		if err != nil || !pattern.MatchString(id) || seen[id] {
			t.Fatalf("invalid or repeated UUIDv7: %q, %v", id, err)
		}
		seen[id] = true
	}
}
