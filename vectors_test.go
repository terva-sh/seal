package seal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// vector is one entry of testdata/vectors.json, which terva's own
// packages/secrets wrote. The file is the compatibility contract with terva's
// "enc:age:v2:" fields: a field terva sealed must open here, and Seal must
// write the same plaintext terva does for the same input.
type vector struct {
	Name        string   `json:"name"`
	Field       string   `json:"field"`
	OpenAt      string   `json:"open_at"`
	Identities  []string `json:"identities"`
	Expect      string   `json:"expect"`
	Value       *string  `json:"value"`
	SealBinding *string  `json:"seal_binding"`
	SealValue   *string  `json:"seal_value"`
	Plaintext   *string  `json:"plaintext"`
	Terva       string   `json:"terva"`
}

type vectorFile struct {
	Seeds      map[string]string `json:"seeds"`
	Recipients map[string]string `json:"recipients"`
	Vectors    []vector          `json:"vectors"`
}

func loadVectors(t *testing.T) (vectorFile, map[string]*age.X25519Identity) {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	ids := map[string]*age.X25519Identity{}
	for name, seed := range f.Seeds {
		ids[name] = derive(seed)
		// The recorded recipient pins the derivation: a drift in it would
		// otherwise surface as every vector failing to open.
		if got := ids[name].Recipient().String(); got != f.Recipients[name] {
			t.Fatalf("identity %s derives recipient %s, the file records %s", name, got, f.Recipients[name])
		}
	}
	return f, ids
}

func TestTervaVectorsOpen(t *testing.T) {
	f, ids := loadVectors(t)
	want := map[string]error{"mismatch": ErrMismatch, "version": ErrVersion, "not_sealed": ErrNotSealed}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var open []age.Identity
			for _, name := range v.Identities {
				open = append(open, ids[name])
			}
			got, err := Open(v.OpenAt, v.Field, open...)
			switch v.Expect {
			case "ok":
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if v.Value == nil || got != *v.Value {
					t.Fatalf("Open = %q, want %v", got, v.Value)
				}
			case "no_identity":
				var none *age.NoIdentityMatchError
				if !errors.As(err, &none) {
					t.Fatalf("Open error = %v, want no matching identity", err)
				}
			case "malformed":
				if err == nil {
					t.Fatalf("Open accepted a malformed field and returned %q", got)
				}
				for _, sentinel := range want {
					if errors.Is(err, sentinel) {
						t.Fatalf("Open error %v is a sentinel; a malformed field is none of them", err)
					}
				}
			default:
				sentinel, ok := want[v.Expect]
				if !ok {
					t.Fatalf("unknown expectation %q", v.Expect)
				}
				if !errors.Is(err, sentinel) {
					t.Fatalf("Open error = %v, want %v", err, sentinel)
				}
			}
			if err != nil && v.Value != nil && *v.Value != "" && strings.Contains(err.Error(), *v.Value) {
				t.Fatalf("error quotes the value: %v", err)
			}
		})
	}
}

// Seal must write the plaintext terva writes for the same binding and value,
// byte for byte, so a field sealed here is indistinguishable from one terva
// sealed once decrypted.
func TestSealWritesTervasPlaintext(t *testing.T) {
	f, ids := loadVectors(t)
	n := 0
	for _, v := range f.Vectors {
		if v.Plaintext == nil {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			field, err := Seal(*v.SealBinding, *v.SealValue, ids["A"].Recipient())
			if err != nil {
				t.Fatal(err)
			}
			got := decryptRaw(t, field, ids["A"])
			if string(got) != *v.Plaintext {
				t.Fatalf("plaintext\n got %s\nwant %s", got, *v.Plaintext)
			}
		})
	}
	if n == 0 {
		t.Fatal("no vector records a plaintext")
	}
}

// decryptRaw opens a field's age file without parsing its plaintext.
func decryptRaw(t *testing.T, field string, id age.Identity) []byte {
	t.Helper()
	b64, ok := strings.CutPrefix(field, Prefix)
	if !ok {
		t.Fatalf("field lacks the prefix: %.20q", field)
	}
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
