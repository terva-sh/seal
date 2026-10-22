// Package seal reads and writes sealed fields: single secret values,
// encrypted with age to X25519 recipients and bound to the location they are
// stored at.
//
// A sealed field is one line of text:
//
//	enc:age:v2:<standard base64 of a binary age file>
//
// The age file's plaintext is the JSON object {"b":binding,"v":value}. The
// binding names where the value belongs, such as a configuration key path, and
// Open refuses a field whose binding differs from the location it was read
// from. docs/format.md in this module is the full specification.
//
// # What the binding is for
//
// age authenticates a ciphertext, so nobody without the identity can alter a
// sealed value or read it. What age cannot stop is relocation. Configuration
// files are usually writable by more parties than may read their secrets, and
// a writer who cannot open a value can still move it to another key, where the
// program opens it and hands it to a different consumer. Sealing the location
// beside the value turns that move into an error at the point of use.
//
// The binding does not stop a writer from minting a new value: the recipient
// is public by design, so anyone holding it can seal any value for any
// location, exactly as they could write plaintext there. It does not stop a
// writer from deleting a value, or from putting back an older value that was
// sealed for the same location. Retiring the identity that opens old values is
// the answer to the last one.
//
// # Keys
//
// An identity is an age X25519 identity in the age-keygen file format, read
// with ParseIdentity. Sealing needs only the recipient, so tools and people
// can seal new values without access to the identity.
//
// # Stability
//
// The field format is fixed: a field sealed by any release opens in every
// later release. A different format gets a different prefix. Every exported
// symbol is stable, and before v1.0.0 one can change only in a minor release,
// with a note in the release notes. README.md has the full promise.
package seal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

// Prefix begins every sealed field. The version in it names the plaintext
// shape, so a later shape can sit beside this one during a migration.
const Prefix = "enc:age:v2:"

// family begins every field of the "enc:age:" scheme, of any version.
const family = "enc:age:"

var (
	// ErrNotSealed reports a string that does not carry the "enc:age:"
	// prefix. Whether such a string is acceptable plaintext is the caller's
	// decision, not this package's.
	ErrNotSealed = errors.New("seal: value is not sealed")

	// ErrVersion reports an "enc:age:" field of a version this package does
	// not open, such as the unbound "enc:age:v1:" encoding, which cannot
	// prove where it belongs.
	ErrVersion = errors.New("seal: unsupported sealed-field version")

	// ErrMismatch reports a field bound to a location other than the one it
	// was read from: it has been moved.
	ErrMismatch = errors.New("seal: value is bound to a different location")
)

// Binding joins a scope and a location into a binding, as scope|location.
// The scope names the file or program the value belongs to, and the location
// is a path within it, in whatever vocabulary that scope already uses, such
// as a dotted key path or a JSON Pointer. A binding only has to be stable and
// unambiguous within its scope.
//
// Binding is a convention, not part of the format: any non-empty string is a
// valid binding.
func Binding(scope, location string) string { return scope + "|" + location }

// IsSealed reports whether s begins with Prefix. A string carrying another
// "enc:age:" version is not reported as sealed, because Open would refuse it.
func IsSealed(s string) bool { return strings.HasPrefix(s, Prefix) }

// bound is the plaintext of a field. Short keys because they are encrypted
// overhead on every value; the shape is closed, so another member would be a
// new version.
type bound struct {
	B string `json:"b"`
	V string `json:"v"`
}

// Seal encrypts value, bound to binding, to every recipient, and returns the
// field. Any of the recipients' identities opens it.
//
// Seal refuses an empty binding, because a field nobody can check is the
// unbound encoding under a new prefix. It refuses a binding or value that is
// not valid UTF-8, because JSON would replace the invalid bytes and the field
// would open to a different string.
func Seal(binding, value string, recipients ...age.Recipient) (string, error) {
	if binding == "" {
		return "", errors.New("seal: refusing to seal a value with an empty binding")
	}
	if !utf8.ValidString(binding) || !utf8.ValidString(value) {
		return "", errors.New("seal: binding and value must be valid UTF-8")
	}
	if len(recipients) == 0 {
		return "", errors.New("seal: no recipients")
	}
	plain, err := json.Marshal(bound{B: binding, V: value})
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	return Prefix + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Open decrypts field with the first identity that fits and returns its value,
// provided the field is bound to binding. It is the call to make wherever a
// value is used.
//
// The error wraps ErrNotSealed when field has no "enc:age:" prefix,
// ErrVersion for a version other than v2, and ErrMismatch when the field is
// bound elsewhere. The mismatch error names both bindings and never the value.
func Open(binding, field string, identities ...age.Identity) (string, error) {
	got, value, err := OpenUnchecked(field, identities...)
	if err != nil {
		return "", err
	}
	if got != binding {
		return "", fmt.Errorf("%w: sealed for %q, found at %q", ErrMismatch, got, binding)
	}
	return value, nil
}

// OpenUnchecked decrypts field and returns the binding it carries with its
// value, without comparing the binding to anything.
//
// It exists for tools that rewrite fields in place, such as re-sealing to a
// new recipient, and need to report a value that has been moved rather than
// fail on it. Code that uses the value calls Open.
func OpenUnchecked(field string, identities ...age.Identity) (binding, value string, err error) {
	b64, ok := strings.CutPrefix(field, Prefix)
	if !ok {
		if strings.HasPrefix(field, family) {
			return "", "", fmt.Errorf("%w: only %q fields open", ErrVersion, Prefix)
		}
		return "", "", ErrNotSealed
	}
	if len(identities) == 0 {
		return "", "", errors.New("seal: no identities")
	}
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("seal: decode base64: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), identities...)
	if err != nil {
		return "", "", fmt.Errorf("seal: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return "", "", fmt.Errorf("seal: %w", err)
	}
	bv, err := parseBound(plain)
	if err != nil {
		return "", "", err
	}
	return bv.B, bv.V, nil
}

// parseBound reads a field's plaintext: a JSON object with exactly the string
// members "b" and "v", and a non-empty "b".
func parseBound(plain []byte) (bound, error) {
	bad := func(why string) (bound, error) {
		return bound{}, fmt.Errorf("seal: plaintext is not a bound value: %s", why)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(plain, &members); err != nil {
		return bad("not a JSON object")
	}
	if len(members) != 2 {
		return bad(`want exactly the members "b" and "v"`)
	}
	var bv bound
	for name, dst := range map[string]*string{"b": &bv.B, "v": &bv.V} {
		raw, ok := members[name]
		if !ok {
			return bad(fmt.Sprintf("missing member %q", name))
		}
		if err := json.Unmarshal(raw, dst); err != nil || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
			return bad(fmt.Sprintf("member %q is not a string", name))
		}
	}
	if bv.B == "" {
		return bad("empty binding")
	}
	return bv, nil
}
