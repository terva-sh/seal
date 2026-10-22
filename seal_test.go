package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRoundTrip(t *testing.T) {
	id := newIdentity(t)
	at := Binding("config", "extensions.weather.api_key")
	for _, value := range []string{"hunter2", "", "päss <&> \"q\" \\ \U0001F511", strings.Repeat("x", 70000)} {
		field, err := Seal(at, value, id.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		if !IsSealed(field) {
			t.Fatalf("sealed field lacks the prefix: %.20q", field)
		}
		if strings.ContainsAny(field, "\r\n") {
			t.Fatal("sealed field is not one line")
		}
		got, err := Open(at, field, id)
		if err != nil {
			t.Fatal(err)
		}
		if got != value {
			t.Fatalf("round trip of a %d-byte value came back as %d bytes", len(value), len(got))
		}
		b, v, err := OpenUnchecked(field, id)
		if err != nil || b != at || v != value {
			t.Fatalf("OpenUnchecked = (%q, %d bytes, %v)", b, len(v), err)
		}
	}
}

// A value sealed for one location must not open at another. The files that
// hold sealed values are writable by parties who cannot open them, and moving
// a value is the attack the binding exists to stop.
func TestOpenRefusesAMovedValue(t *testing.T) {
	id := newIdentity(t)
	here := Binding("config", "image.backends.local.api_key")
	there := Binding("config", "extensions.weather.api_key")
	field, err := Seal(here, "hunter2", id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(there, field, id)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Open at another binding: %v, want ErrMismatch", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the mismatch error quotes the value: %v", err)
	}
	// The same identity opens it where it belongs, so the refusal is the
	// binding and not the key.
	if got, err := Open(here, field, id); err != nil || got != "hunter2" {
		t.Fatalf("Open at its own binding = (%q, %v)", got, err)
	}
	// OpenUnchecked reports where it was sealed for, for a tool that re-seals.
	if b, _, err := OpenUnchecked(field, id); err != nil || b != here {
		t.Fatalf("OpenUnchecked binding = (%q, %v)", b, err)
	}
}

// An empty binding would mint a value that nothing can move-check: the
// unbound encoding wearing the bound prefix.
func TestSealRefusesAnEmptyBinding(t *testing.T) {
	if _, err := Seal("", "hunter2", newIdentity(t).Recipient()); err == nil {
		t.Fatal("sealed a value with an empty binding")
	}
}

// JSON replaces invalid UTF-8 with U+FFFD, so sealing such a value would
// return a field that opens to a different string.
func TestSealRefusesInvalidUTF8(t *testing.T) {
	r := newIdentity(t).Recipient()
	if _, err := Seal("config|a", "bad\xff", r); err == nil {
		t.Fatal("sealed a value that is not UTF-8")
	}
	if _, err := Seal("config|\xff", "ok", r); err == nil {
		t.Fatal("sealed under a binding that is not UTF-8")
	}
}

func TestSealAndOpenNeedKeys(t *testing.T) {
	if _, err := Seal("config|a", "v", nil...); err == nil {
		t.Fatal("sealed to no recipients")
	}
	field, err := Seal("config|a", "v", newIdentity(t).Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open("config|a", field); err == nil {
		t.Fatal("opened with no identities")
	}
}

func TestOpenClassifiesWhatIsNotAField(t *testing.T) {
	id := newIdentity(t)
	cases := map[string]error{
		"hunter2":             ErrNotSealed,
		"":                    ErrNotSealed,
		"enc:age:v1:AAAA":     ErrVersion,
		"enc:age:v3:AAAA":     ErrVersion,
		"enc:age:v2":          ErrVersion,
		"ENC:AGE:V2:AAAA":     ErrNotSealed,
		"enc:age:v2:not*b64!": nil,
	}
	for in, want := range cases {
		_, err := Open("config|a", in, id)
		if err == nil {
			t.Errorf("Open(%q) succeeded", in)
			continue
		}
		if want != nil && !errors.Is(err, want) {
			t.Errorf("Open(%q) = %v, want %v", in, err, want)
		}
		if IsSealed(in) != strings.HasPrefix(in, Prefix) {
			t.Errorf("IsSealed(%q) disagrees with the prefix", in)
		}
	}
}

// Several recipients, then a ring of identities: what makes rotating a key
// safe to interrupt.
func TestRecipientsAndIdentityRings(t *testing.T) {
	old, next := newIdentity(t), newIdentity(t)
	field, err := Seal("config|a", "v", old.Recipient(), next.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []age.Identity{old, next} {
		if got, err := Open("config|a", field, id); err != nil || got != "v" {
			t.Fatalf("an identity sealed to did not open it: (%q, %v)", got, err)
		}
	}
	onlyNext, err := Seal("config|a", "v", next.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open("config|a", onlyNext, old); err == nil {
		t.Fatal("an identity not sealed to opened the field")
	}
	if got, err := Open("config|a", onlyNext, old, next); err != nil || got != "v" {
		t.Fatalf("a ring holding the right identity did not open it: (%q, %v)", got, err)
	}
}

func TestOpenRefusesAPlaintextThatIsNotABoundValue(t *testing.T) {
	id := newIdentity(t)
	for _, plain := range []string{
		`hunter2`,
		`null`,
		`[]`,
		`{"b":"config|a"}`,
		`{"v":"x"}`,
		`{"b":"","v":"x"}`,
		`{"b":null,"v":"x"}`,
		`{"b":"config|a","v":null}`,
		`{"b":"config|a","v":1}`,
		`{"b":"config|a","v":"x","z":"y"}`,
	} {
		field := sealRaw(t, plain, id.Recipient())
		if v, err := Open("config|a", field, id); err == nil {
			t.Errorf("opened plaintext %s as %q", plain, v)
		} else if errors.Is(err, ErrMismatch) || errors.Is(err, ErrNotSealed) || errors.Is(err, ErrVersion) {
			t.Errorf("plaintext %s: %v is a sentinel, want a malformed-plaintext error", plain, err)
		}
	}
}

// sealRaw writes a v2 field around an arbitrary plaintext, as a writer other
// than Seal could.
func sealRaw(t *testing.T, plain string, r age.Recipient) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return Prefix + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestParseIdentity(t *testing.T) {
	id := newIdentity(t)
	content := "# created: 2026-10-22T00:00:00Z\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	parsed, err := ParseIdentity(content)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Recipient().String() != id.Recipient().String() {
		t.Fatal("parsed identity derives a different recipient")
	}
	if _, err := ParseIdentity("  \r\n" + id.String() + "\r\n\n"); err != nil {
		t.Fatalf("CRLF and surrounding blank lines: %v", err)
	}
	if _, err := ParseIdentity("# only comments\n"); err == nil {
		t.Fatal("comment-only content parsed as an identity")
	}
	if _, err := ParseIdentity(id.String() + "\n" + id.String() + "\n"); err == nil {
		t.Fatal("two key lines parsed; the file is ambiguous")
	}
	_, err = ParseIdentity("password1hunter2xyz\n")
	if err == nil {
		t.Fatal("a line that is not a key parsed")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "password") {
		t.Fatalf("the error quotes the line: %v", err)
	}
}

func TestParseRecipient(t *testing.T) {
	id := newIdentity(t)
	r, err := ParseRecipient("  " + id.Recipient().String() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if r.String() != id.Recipient().String() {
		t.Fatal("recipient round trip mismatch")
	}
	if _, err := ParseRecipient(id.String()); err == nil {
		t.Fatal("an identity parsed as a recipient")
	}
}

func TestBinding(t *testing.T) {
	if got := Binding("config", "a.b"); got != "config|a.b" {
		t.Fatalf("Binding = %q", got)
	}
}
