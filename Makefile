PLUGIN_NAME := vault-plugin-secrets-aap

.PHONY: build test unit race integration fmt-check vet mod-verify tidy-check vulncheck release-check check

build:
	CGO_ENABLED=0 go build -trimpath -o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

unit:
	go test ./...

test: unit

race:
	go test -race ./...

integration:
	go test -tags=integration ./test/integration

fmt-check:
	test -z "$$(gofmt -l $$(git ls-files '*.go'))"

vet:
	go vet ./...

mod-verify:
	go mod verify

tidy-check:
	go mod tidy -diff

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

release-check:
	goreleaser release --snapshot --clean

check:
	$(MAKE) fmt-check
	$(MAKE) mod-verify
	$(MAKE) tidy-check
	$(MAKE) unit
	$(MAKE) race
	$(MAKE) vet
	$(MAKE) build
