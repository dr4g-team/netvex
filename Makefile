BINARY := bin/netvex
PREFIX ?= $(HOME)/.local
VERSION ?= $(shell tr -d '\n' < VERSION)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE := github.com/drag-team/netvex
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
FUZZTIME ?= 30s
COVERAGE_MIN ?= 70
LDFLAGS := -s -w -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: all build check clean cover cross-check fmt fmt-check fuzz install lint race release-check reproducibility-check test uninstall verify version vet vuln

all: check build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/netvex

check: fmt-check vet test race

verify: check lint vuln cover

lint:
	go run $(STATICCHECK) ./...

vuln:
	go run $(GOVULNCHECK) ./...

cover:
	@set -eu; tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; \
	go test -coverprofile="$$tmp" ./... >/dev/null; \
	total="$$(go tool cover -func="$$tmp" | awk '/^total:/ {gsub("%","",$$3); print $$3}')"; \
	printf 'total coverage %s%% (minimum %s%%)\n' "$$total" '$(COVERAGE_MIN)'; \
	awk -v t="$$total" -v m='$(COVERAGE_MIN)' 'BEGIN {exit !(t+0 >= m+0)}'

fuzz:
	@set -eu; \
	for file in $$(grep -rlE '^func Fuzz' --include='*_test.go' internal); do \
		package="./$$(dirname "$$file")"; \
		for name in $$(grep -hoE '^func Fuzz[A-Za-z0-9]+' "$$file" | cut -d' ' -f2); do \
			printf 'fuzzing %s %s\n' "$$package" "$$name"; \
			go test "$$package" -run '^$$' -fuzz "^$$name$$" -fuzztime='$(FUZZTIME)'; \
		done; \
	done

cross-check:
	@set -eu; tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	for target in linux/amd64 linux/386 linux/arm linux/arm64 linux/riscv64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64 netbsd/amd64 dragonfly/amd64 illumos/amd64 solaris/amd64 aix/ppc64; do \
		os="$${target%/*}"; arch="$${target#*/}"; suffix=""; test "$$os" != windows || suffix=.exe; \
		printf 'building %s\n' "$$target"; \
		if test "$$target" = linux/arm; then \
			CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" GOARM=7 go build -mod=readonly -trimpath -buildvcs=false -o "$$tmp/netvex-linux-armv7" ./cmd/netvex; \
		else \
			CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -mod=readonly -trimpath -buildvcs=false -o "$$tmp/netvex-$$os-$$arch$$suffix" ./cmd/netvex; \
		fi; \
	done

reproducibility-check:
	@set -eu; tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o "$$tmp/first" ./cmd/netvex; \
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o "$$tmp/second" ./cmd/netvex; \
	cmp "$$tmp/first" "$$tmp/second"; \
	printf 'reproducible binary %s\n' "$$(sha256sum "$$tmp/first" | cut -d' ' -f1)"

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -d cmd internal; exit 1; }

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/netvex

version:
	@printf '%s\n' '$(VERSION)'

release-check:
	@case '$(VERSION)' in ''|*-dev) printf '%s\n' 'VERSION must contain a stable release version' >&2; exit 1;; esac
	@printf '%s\n' '$(VERSION)' | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { printf '%s\n' 'VERSION must use stable Semantic Versioning' >&2; exit 1; }
	@test "$$(cat VERSION)" = '$(VERSION)' || { printf '%s\n' 'VERSION override does not match the canonical VERSION file' >&2; exit 1; }
	@test "$$(git cat-file -t 'v$(VERSION)' 2>/dev/null)" = tag || { printf '%s\n' 'annotated release tag v$(VERSION) is missing' >&2; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-list -n 1 'v$(VERSION)')" || { printf '%s\n' 'release tag does not point to HEAD' >&2; exit 1; }
	@grep -Fq '## [$(VERSION)]' CHANGELOG.md || { printf '%s\n' 'CHANGELOG.md has no section for $(VERSION)' >&2; exit 1; }
	@test -z "$$(git status --porcelain)" || { printf '%s\n' 'working tree is not clean' >&2; exit 1; }
	@$(MAKE) verify

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/netvex

clean:
	rm -rf bin dist
