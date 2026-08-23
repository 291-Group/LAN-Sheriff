.DEFAULT_GOAL := build

BINARY      := lan-sheriff
PKG         := github.com/291-Group/LAN-Sheriff
CLI_PKG     := $(PKG)/internal/cli
# Set here rather than derived from `git describe`, and the difference is worth
# a paragraph because it is the version people will read.
#
# describe produced v0.0.1-rehearsal.9-56-g9891281: a tag nobody chose, plus a
# commit distance and a hash. The distance duplicates BUILD below and the hash
# is already stamped as COMMIT, so two thirds of that string was noise sitting
# in the place a reader looks to answer "which version am I running".
#
# The release tag is what the published archives are stamped with: goreleaser
# uses {{.Version}} from the tag, so a release cannot disagree with its own name.
# This value is what somebody building from source gets, and the README tells
# people that building from source is one command, so it has to agree with the
# release rather than trail it.
VERSION     ?= v1.0.1
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
# **The build number: commits reachable from HEAD, plus a base.**
#
# The count rises with every commit, cannot be forgotten, and is the same number
# for anyone who checks out the same tree. That beats a file somebody has to
# remember to bump.
#
# The base is for the one case the count cannot describe on its own.
#
# The number is the commit count, which restarts at 1 in a fresh repository. The
# public repository is a fresh one: its history begins at the first public
# commit, so without this a v1.0.0 that took a hundred and forty-odd builds to
# reach would announce itself as build 1, which understates the thing the number
# exists to say.
#
# Zero here, because in this repository the count is already the whole truth.
# The public repository sets it once, to whatever this repository ended on, and
# from then on both halves add up: base plus the commits made since.
BUILD_BASE  ?= $(shell cat BUILD_BASE 2>/dev/null || echo 0)
BUILD       ?= $(shell echo $$(( $(BUILD_BASE) + $$(git rev-list --count HEAD 2>/dev/null || echo 0) )))

LDFLAGS := -s -w \
	-X '$(CLI_PKG).Version=$(VERSION)' \
	-X '$(CLI_PKG).Commit=$(COMMIT)' \
	-X '$(CLI_PKG).BuildDate=$(BUILD_DATE)' \
	-X '$(CLI_PKG).Build=$(BUILD)'

# Deputy Mode on darwin needs libproc (cgo). Linux and Windows stay cgo-free so
# cross-compilation to a Pi stays trivial.
ifeq ($(shell go env GOOS),darwin)
	CGO := 1
else
	CGO := 0
endif

# Everything the frontend build reads, not just the TypeScript.
#
# This was web/src alone, which meant editing index.html or dropping a file in
# web/public produced "Nothing to be done for `web'" and a dist that silently
# stayed stale. Adding favicons is exactly the change that hits it: the files
# appear, the build reports success, and the icons are simply not there.
WEB_SRC := $(shell find web/src web/public -type f 2>/dev/null) web/index.html

.PHONY: build
build: web ## Build the binary with the dashboard embedded
	CGO_ENABLED=$(CGO) go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/lan-sheriff

.PHONY: run
run: build ## Build and run
	./$(BINARY)

.PHONY: dev
dev: ## Run the backend without rebuilding the frontend (uses the last build)
	CGO_ENABLED=$(CGO) go run ./cmd/lan-sheriff

.PHONY: web
web: internal/web/dist/index.html ## Build the frontend into the embed directory

internal/web/dist/index.html: web/package.json $(WEB_SRC)
	cd web && npm install --no-audit --no-fund && npm run build

.PHONY: test
test: ## Run tests (cgo-free build path too)
	CGO_ENABLED=$(CGO) go test ./...

.PHONY: vet
vet:
	CGO_ENABLED=$(CGO) go vet ./...

.PHONY: lint
lint: ## golangci-lint if present, otherwise vet
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "golangci-lint not installed, running vet"; $(MAKE) vet; fi

.PHONY: check
hygiene: ## Repo checks that no compiler enforces (CSS vars, i18n, the docs)
	@node scripts/check-css-vars.mjs
	@node scripts/check-i18n.mjs
	@node scripts/check-msg-codes.mjs
	@node scripts/check-dist.mjs
	@node scripts/check-downloads.mjs
	@out=$$(bash scripts/release/gate_test.sh) || { echo "$$out"; exit 1; }; echo "$$out" | tail -1

# staticcheck the way CI runs it, over the whole module. Added because it was
# in CI and not here, so `make check` said "What CI runs" while missing the one
# check that actually failed: invisible bidi characters written literally into
# a Go string rather than as escapes (ST1018). A local check that is a subset
# of CI spends a CI run to tell you something your machine could have.
.PHONY: staticcheck
staticcheck: ## staticcheck, over the whole module, as CI does
	@command -v staticcheck >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	@sc=$$(command -v staticcheck || echo "$$(go env GOPATH)/bin/staticcheck"); "$$sc" ./...

# gofmt exactly as CI runs it, over the same directories.
#
# Added for the same reason staticcheck was: `make check` claimed to be "what CI
# runs" and was a subset of it, so a formatting slip passed locally and failed
# on the runner. This one arrived by shortening an address in a const block,
# which changed the column width and left the trailing comments misaligned:
# invisible while reading the diff, fatal to the build, and a full CI run spent
# to say something a second of local work could have.
.PHONY: fmtcheck
fmtcheck: ## Fail if anything under internal or cmd is not gofmt'd
	@unformatted="$$(gofmt -l internal cmd)"; \
	if [ -n "$$unformatted" ]; then \
	  echo "not gofmt'd:"; echo "$$unformatted"; \
	  echo "run: gofmt -w internal cmd"; exit 1; \
	fi; \
	echo "gofmt: clean"

# go.mod tidy, asserted rather than assumed, exactly as CI does it.
.PHONY: modcheck
modcheck: ## Fail if go.mod or go.sum would change under go mod tidy
	@cp go.mod /tmp/go.mod.check && cp go.sum /tmp/go.sum.check
	@go mod tidy
	@if ! diff -q /tmp/go.mod.check go.mod >/dev/null || ! diff -q /tmp/go.sum.check go.sum >/dev/null; then \
	  cp /tmp/go.mod.check go.mod; cp /tmp/go.sum.check go.sum; \
	  echo "go.mod or go.sum is not tidy; run 'go mod tidy'"; exit 1; \
	fi; \
	echo "go.mod: tidy"

# The frontend type checker, which the build does not run: `vite build` strips
# types without checking them, so a type error ships a working bundle and fails
# only on the runner.
.PHONY: typecheck
typecheck: ## TypeScript, as CI runs it
	@# Installs first if it has to, because a fresh clone has no node_modules.
	@#
	@# The dashboard bundle is committed, so `make build` needs no npm at all and
	@# a clone builds with Go alone. That is deliberate, and it means the first
	@# command a contributor runs after cloning is also the first one to need
	@# node_modules. Without this, `make check` died in npx with advice about
	@# yarn, while CONTRIBUTING.md says that if it fails here it is a bug in
	@# `make check`. It was.
	@[ -d web/node_modules ] || (echo "installing the frontend toolchain, once"; cd web && npm install --no-audit --no-fund >/dev/null)
	@cd web && npx tsc --noEmit && echo "typescript: clean"

check: fmtcheck modcheck vet staticcheck typecheck test hygiene ## What CI runs

.PHONY: patrol
patrol: web ## Build with Patrol Mode (needs libpcap/Npcap)
	CGO_ENABLED=1 go build -tags patrol -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/lan-sheriff

.PHONY: datasets
datasets: ## Vendor the embedded GeoIP country database
	./scripts/fetch-datasets.sh

.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist internal/web/dist web/dist web/node_modules

# One source of truth for the version, so the release scripts cannot drift from
# what `make` stamps. They used to run their own `git describe`, which meant
# three places to change and two of them easy to miss.
.PHONY: print-version
print-version: ## Print the version string that builds stamp
	@echo $(VERSION)

.PHONY: print-build
print-build: ## Print the build number that builds stamp
	@echo $(BUILD)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
