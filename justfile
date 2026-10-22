# seal dev tasks. `just` lists them.
#
# `just ci` runs every check a source checkout can run.
# `just ci-internal` also checks the internal ticket store and the release
# tooling, and is what the internal CI workflow runs.

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Every build and test is cgo-free.
export CGO_ENABLED := "0"

# Every GOOS/GOARCH pair that must build without cgo.
targets := "linux/amd64 linux/arm64 darwin/arm64 windows/amd64"

# The only modules the build may depend on, besides the standard library:
# age and what age itself requires.
allowed_modules := "filippo.io/age filippo.io/hpke golang.org/x/crypto golang.org/x/sys"

default:
    @just --list

# Build every package for this platform.
build:
    go build ./...

# Run the tests.
test:
    go test ./...

# go vet.
vet:
    go vet ./...

# Rewrite sources with gofmt.
fmt:
    gofmt -w .

# Fail if gofmt would change a file.
fmt-check:
    @diff=$(gofmt -l .); if [ -n "$diff" ]; then echo "gofmt issues in:"; echo "$diff"; exit 1; fi

# Fail if the build links a module outside allowed_modules. A new
# dependency is a decision for a ticket, not a side effect of a change.
deps-check:
    #!/usr/bin/env bash
    set -euo pipefail
    allowed=" {{allowed_modules}} "
    bad=0
    for m in $(go list -deps -f '{{"{{"}}with .Module{{"}}"}}{{"{{"}}.Path{{"}}"}}{{"{{"}}end{{"}}"}}' ./... | sort -u); do
        if [ "$m" = "terva.sh/seal" ]; then continue; fi
        if [[ "$allowed" != *" $m "* ]]; then echo "unexpected module in the build: $m"; bad=1; fi
    done
    exit $bad

# vet, gofmt, and the dependency check.
lint: vet fmt-check deps-check

# Build every package for every target.
cross:
    for t in {{targets}}; do \
        echo "== $t"; \
        GOOS=${t%/*} GOARCH=${t#*/} go build ./...; \
    done

# Validate the ticket store without writing anything.
tickets:
    git ticket check --fix --dry-run --strict

# The public release tooling's offline tests, and the leak check over the
# public tree HEAD would publish. Both must pass. release/README.md is the
# procedure.
release-tools:
    cd release && python3 -B -m unittest -q
    python3 -B release/publish.py candidate HEAD

# Every check a source checkout can run.
ci: lint test cross

# The internal CI gate: ci, plus the ticket store and the release tooling.
ci-internal: ci tickets release-tools
