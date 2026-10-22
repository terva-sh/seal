# seal

seal is a Go module for sealed fields: single secret values in a
configuration file, encrypted with [age](https://age-encryption.org) and
bound to the key they are stored at.

```toml
[discord]
token = "enc:age:v2:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBC..."
```

The file stays readable and diffable. Someone who reads it, a person or a
model that copies it into a transcript, learns nothing about the token.
Someone who can write it but cannot open its values cannot move the
token to another key, such as a webhook URL they control: the value was
sealed for `discord.token`, and the program refuses to open it anywhere
else.

```go
import "terva.sh/seal"

id, err := seal.ParseIdentity(keyFile) // an age-keygen key file
at := seal.Binding("mybot", "discord.token")

field, err := seal.Seal(at, token, id.Recipient()) // write this to the file
token, err := seal.Open(at, field, id)              // at the point of use
```

`Open` returns `ErrMismatch` for a value sealed for another key,
`ErrNotSealed` for a plaintext string, and `ErrVersion` for a sealed
field of a version it does not open. Sealing needs only the recipient,
which is public, so a tool or a person can seal a new value without the
key.

The format is specified in [docs/format.md](docs/format.md), with test
vectors in [testdata/vectors.json](testdata/vectors.json).

## Getting it

```sh
go get terva.sh/seal
```

The module lives at [github.com/terva-sh/seal](https://github.com/terva-sh/seal),
which receives each release. Pin a tagged version; [Stability](#stability)
says what each kind of release may change.

## Where it comes from

The format is terva's: [terva](https://terva.sh) seals the secrets in
its own configuration as `enc:age:v2:` fields. This module is the format
extracted from terva's `packages/secrets` so that other programs can
read and write the same fields without depending on terva, and so that
the format keeps a stability promise of its own. terva's fields open
here and this module's fields open in terva; the test vectors were
written by terva's implementation. The first program to use it outside
terva is [airut](https://github.com/terva-sh/airut), for secrets in a
bot's TOML configuration.

## API

| Symbol | Purpose |
|---|---|
| `Seal(binding, value, recipients...)` | Encrypt a value, bound to a location, to one or more recipients. |
| `Open(binding, field, identities...)` | Decrypt a field, refusing it unless it was sealed for `binding`. |
| `OpenUnchecked(field, identities...)` | Decrypt a field and report its binding, for tools that re-seal fields in place. |
| `IsSealed(s)` | Report whether a string carries the `enc:age:v2:` prefix. |
| `Binding(scope, location)` | Join a scope and a location as `scope\|location`, the conventional binding. |
| `ParseIdentity(content)` | Read the one identity in an age-keygen key file. |
| `ParseRecipient(s)` | Parse an `age1...` recipient. |
| `Prefix` | `"enc:age:v2:"`. |
| `ErrNotSealed`, `ErrVersion`, `ErrMismatch` | What `Open` reports, for `errors.Is`. |

Keys are age's own types, `*age.X25519Identity` and
`*age.X25519Recipient`, from [filippo.io/age](https://pkg.go.dev/filippo.io/age).
Generate one with `age-keygen` or `age.GenerateX25519Identity`.

Where a program keeps its key, and how it rotates one, is the program's
policy, and this module has none.

## Stability

- **The format is fixed.** A field sealed by any release opens in every
  later release. A different format gets a different prefix, and `Open`
  keeps reading `enc:age:v2:`.
- **The API is stable.** Every exported symbol is stable unless its doc
  comment opens a paragraph with `Unstable:`, and none does today.
  Before v1.0.0 a stable symbol can change only in a minor release, and
  each change gets a migration note in the release notes. A patch
  release never changes one.
- **age's types are part of the API.** The signatures name
  `filippo.io/age` types, and the module requires age v1.
- **The Go version is part of the promise.** Raising the `go` line in
  go.mod waits for a minor release.

Every build is cgo-free (`CGO_ENABLED=0`).

## Development

```sh
just ci     # vet, gofmt, the dependency check, tests, cross-builds
```

## License

MIT. See [LICENSE](LICENSE).
