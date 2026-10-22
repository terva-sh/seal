# The sealed-field format

This document specifies version 2 of the sealed-field format, the
encoding that `terva.sh/seal` reads and writes. It is complete enough to
write a compatible implementation in another language. The key words
MUST, MUST NOT, SHOULD, and MAY are used as RFC 2119 defines them.

A sealed field is one secret value, such as an API token in a
configuration file, encrypted so that a reader of the file learns
nothing about it, and bound to the location it is stored at so that it
cannot be moved to another one.

## Overview

```text
enc:age:v2:YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBC...
\_________/\______________________________________________/
  prefix      standard base64 of a binary age file
```

The age file's plaintext is a JSON object:

```json
{"b":"config|extensions.weather.api_key","v":"hunter2"}
```

`b` is the binding, which names the location. `v` is the value.

## The field

A field is the ASCII text `enc:age:v2:` followed by the base64 encoding
of an age file.

- The prefix is case-sensitive.
- The encoding is standard base64 with the `+` and `/` alphabet and `=`
  padding, as RFC 4648 section 4 defines it. It is not the URL-safe
  alphabet, and padding is not optional.
- A writer MUST NOT put whitespace or line breaks anywhere in a field. A
  field is one line, so it survives any configuration format that holds
  a single-line string.
- A reader SHOULD reject a field whose base64 text is malformed. This
  implementation tolerates carriage returns and line feeds inside the
  base64 text, because Go's decoder skips them, and rejects everything
  else.

A field is a string value of whatever file holds it. In JSON it is a
JSON string, in TOML a TOML string. This format does not define how the
file marks a value as sealed beyond the prefix.

## The age file

The decoded bytes are an age file in the binary format of the age
specification, version 1 (`age-encryption.org/v1`), not the ASCII-armored
format.

- A writer MUST encrypt to one or more X25519 recipients (`age1...`). Any
  of the matching identities opens the field. Sealing to several
  recipients is how a field stays readable while a key is replaced.
- A reader MAY offer several identities. It opens the field with
  whichever one matches a recipient stanza.
- The recipient is public. Anyone holding it can seal a value, without
  access to the identity.

An identity is stored in the age-keygen file format: one
`AGE-SECRET-KEY-1...` line, with any number of blank lines and lines
beginning with `#` around it. This implementation's `ParseIdentity`
refuses a file with more than one key line.

age authenticates the whole file, so a reader that opens a field knows
the plaintext is what a holder of the recipient wrote.

## The plaintext

The plaintext is a UTF-8 JSON object, RFC 8259, with exactly two
members, both strings:

| Member | Meaning | Constraint |
|---|---|---|
| `b` | The binding: the location the value belongs to. | Non-empty. |
| `v` | The value. | Any string, including the empty string. |

- A writer MUST write exactly these two members, and MUST NOT write a
  binding that is empty.
- A writer SHOULD write compact JSON with `b` first. This
  implementation does, and escapes `<`, `>`, `&`, U+2028, and U+2029 as
  `<`, `>`, `&`, ` `, and ` `, which is what Go's
  encoder writes. Other writers do not escape them. Both are valid JSON.
- A writer MUST refuse a binding or value that is not valid UTF-8, rather
  than replace the invalid bytes. A replaced value would open to a
  different string than the one sealed.
- A reader MUST accept any valid JSON spelling of the object: either
  member order, whitespace between tokens, and any valid string escape.
- A reader MUST reject a plaintext that is not a JSON object, that lacks
  `b` or `v`, whose `b` or `v` is not a string, whose `b` is empty, or
  that has any other member. The shape is closed: a new member would be a
  new version of the format, with a new prefix.
- A reader's handling of a repeated member name is unspecified. A
  writer MUST NOT repeat one. This implementation keeps the last.

## Bindings

A binding is an opaque, non-empty string. Readers compare bindings byte
for byte, with no normalization of case, Unicode, or path syntax.

The binding names the place a value is stored, in a vocabulary chosen by
the program that owns the file. The convention this module's `Binding`
function writes is `scope|location`:

- `scope` names the file or program the value belongs to, such as
  `config` or `conn:discord-ext`.
- `location` is a path within it, in the syntax that scope already
  uses: a dotted key path such as `discord.token`, a TOML key path, or an
  RFC 6901 JSON Pointer such as `/auth/bot_token`.

A binding only needs to be stable and unambiguous within its scope.
Two programs that read the same file MUST agree on the binding for each
location, or each will refuse the other's values.

### Opening a field

A program opens a field with the binding of the location it read the
field from. It MUST refuse the field when the sealed binding differs, and
SHOULD report both bindings so that a person can see where the value
came from. It MUST NOT include the value in that report.

A tool that rewrites fields in place, for example to seal them to a new
recipient, MAY open a field without comparing its binding, in order to
report a value that has been moved. It MUST NOT re-seal a moved value
under its new location, because that would complete the move.

### What the binding protects

Encryption keeps a value secret from anyone who can read the file. The
binding addresses a different party: one who can write the file but not
open its values. Without a binding, such a writer can move a sealed value
from one key to another, for example from a model provider's API key to
the URL of a webhook the writer controls. The program then opens the
value and sends it to the wrong place, though nobody broke the
encryption.

The binding does not protect against:

- **Minting.** The recipient is public, so a writer can seal any value
  for any location, as they could write a plaintext value there.
- **Deletion.** A writer can remove a field. Only a declaration of which
  locations must hold sealed values detects that.
- **Replay.** A writer can put back an older field that was sealed for
  the same location. Retiring the identity that opens it ends the replay.

## Versions

The prefix carries the version. Every version of this format begins
with `enc:age:`.

| Prefix | Status | Plaintext |
|---|---|---|
| `enc:age:v1:` | Retired. Readers MUST NOT open it at a point of use. | The bare value, with no binding. |
| `enc:age:v2:` | Current. | `{"b":binding,"v":value}` |

A v1 field cannot prove where it belongs. A program that holds v1 fields
re-seals them as v2 with a migration tool of its own. This module does
not open v1 fields. `Open` reports any `enc:age:` field with a version
other than v2 as `ErrVersion`, and a string without the `enc:age:`
prefix as `ErrNotSealed`. Whether such a string is acceptable plaintext
is the calling program's decision.

The v2 format will not change. A field sealed by any release of this
module opens in every later release. A change to the plaintext shape,
the encoding, or the cipher gets a new version prefix, and readers keep
opening v2 for as long as fields of that version can exist.

## Test vectors

`testdata/vectors.json` in this module holds fields written by terva's
own implementation of the format, from which this module was extracted.
Each vector names the binding to open it at, the identities to offer,
and the expected result. Vectors that seal a value also record the exact
plaintext bytes, which this module's writer reproduces.

The vectors' identities are derived from public seeds, so they protect
nothing: the X25519 scalar is the SHA-256 digest of the seed, written as
an `AGE-SECRET-KEY-1` line in Bech32. The file also records each
identity's recipient, which pins the derivation.

## References

- age v1 specification: <https://age-encryption.org/v1>
- RFC 2119, key words: <https://www.rfc-editor.org/rfc/rfc2119>
- RFC 4648, base64: <https://www.rfc-editor.org/rfc/rfc4648>
- RFC 6901, JSON Pointer: <https://www.rfc-editor.org/rfc/rfc6901>
- RFC 8259, JSON: <https://www.rfc-editor.org/rfc/rfc8259>
