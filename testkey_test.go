package seal

// The test vectors' identities are derived from public seeds rather than
// checked in as key lines: the X25519 scalar is SHA-256 of the seed, written
// as an AGE-SECRET-KEY-1 line with the Bech32 encoding below (BIP 173). The
// keys protect nothing, and no key line sits in the tree for a scanner to
// mistake for a credential.

import (
	"crypto/sha256"
	"strings"

	"filippo.io/age"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// polymod is Bech32's checksum function.
func polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32 encodes data under the lowercase human-readable part hrp.
func bech32(hrp string, data []byte) string {
	var five []byte
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		five = append(five, byte(acc<<(5-bits)&31))
	}
	var exp []byte
	for _, c := range hrp {
		exp = append(exp, byte(c>>5))
	}
	exp = append(exp, 0)
	for _, c := range hrp {
		exp = append(exp, byte(c&31))
	}
	mod := polymod(append(append(exp, five...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp + "1")
	for _, v := range five {
		sb.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[mod>>uint(5*(5-i))&31])
	}
	return sb.String()
}

// derive returns the identity for a test seed.
func derive(seed string) *age.X25519Identity {
	k := sha256.Sum256([]byte(seed))
	id, err := age.ParseX25519Identity(strings.ToUpper(bech32("age-secret-key-", k[:])))
	if err != nil {
		panic(err)
	}
	return id
}
