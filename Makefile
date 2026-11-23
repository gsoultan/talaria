VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/gsoultan/talaria/usecase.Version=$(VERSION) -X github.com/gsoultan/talaria/usecase.Commit=$(COMMIT)

.PHONY: all gen check web build test run clean

all: build

## gen: regenerate the kakarot endpoints and transport, the OpenAPI
## document, and the webmail's TypeScript client
gen:
	scripts/kakarot.sh gen
	go run ./cmd/talaria openapi > api/openapi.json
	cd web && bun run gen

## check: kakarot's layer rules, and generated code up to date
check:
	scripts/kakarot.sh check

## web: build the webmail and copy it into the Go embed directory
web:
	cd web && bun install --frozen-lockfile && bun run build
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -R web/dist/. internal/webui/dist/

## build: build a static, stripped binary with the webmail embedded
build: web
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/talaria ./cmd/talaria

test:
	go vet ./...
	go test -race ./...
	cd web && bun run typecheck

run:
	go run ./cmd/talaria -config talaria.example.toml

clean:
	rm -rf bin web/dist
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
