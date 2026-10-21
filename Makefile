PLUGIN_NAME := vault-plugin-secrets-aap

.PHONY: build test fmt vet check

build:
	go build -o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

test:
	go test ./...

fmt:
	gofmt -w ./cmd ./aap

vet:
	go vet ./...

check:
	test -z "$$(gofmt -l ./cmd ./aap)"
	go test ./...
	go vet ./...
