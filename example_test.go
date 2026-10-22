package seal_test

import (
	"errors"
	"fmt"

	"filippo.io/age"
	"terva.sh/seal"
)

// A program seals a secret for the configuration key it is stored at, and
// opens it at that key. Read anywhere else, it refuses.
func Example() {
	id, err := age.GenerateX25519Identity() // in practice, seal.ParseIdentity of the key file
	if err != nil {
		panic(err)
	}
	at := seal.Binding("mybot", "discord.token")

	field, err := seal.Seal(at, "s3cret", id.Recipient())
	if err != nil {
		panic(err)
	}
	fmt.Println(seal.IsSealed(field))

	token, err := seal.Open(at, field, id)
	fmt.Println(token, err)

	_, err = seal.Open(seal.Binding("mybot", "webhook.url"), field, id)
	fmt.Println(errors.Is(err, seal.ErrMismatch))

	_, err = seal.Open(at, "s3cret", id)
	fmt.Println(errors.Is(err, seal.ErrNotSealed))
	// Output:
	// true
	// s3cret <nil>
	// true
	// true
}
