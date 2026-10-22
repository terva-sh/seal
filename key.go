package seal

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
)

// ParseIdentity reads one X25519 identity from key-file content in the
// age-keygen format: blank lines and lines beginning with # around a single
// AGE-SECRET-KEY-1 line.
//
// A second key line is an error rather than ignored. A file that is meant to
// hold the key and holds two is a mistake to report, not a choice to make on
// the caller's behalf. Errors never include the key material.
func ParseIdentity(content string) (*age.X25519Identity, error) {
	var found *age.X25519Identity
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if found != nil {
			return nil, errors.New("seal: key file holds more than one key line")
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			// age's message can quote part of the line, which may be a
			// secret of some other kind, so it is dropped.
			return nil, errors.New("seal: key file holds a line that is not an AGE-SECRET-KEY-1 key")
		}
		found = id
	}
	if found == nil {
		return nil, errors.New("seal: key file holds no AGE-SECRET-KEY-1 line")
	}
	return found, nil
}

// ParseRecipient parses an age1 X25519 recipient, ignoring surrounding
// whitespace such as the newline at the end of a file.
func ParseRecipient(s string) (*age.X25519Recipient, error) {
	r, err := age.ParseX25519Recipient(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("seal: parse recipient: %w", err)
	}
	return r, nil
}
