PLUGIN_NAME := vault-plugin-secrets-aap

.PHONY: build test fmt

build:
	go build -o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

test:
	go test ./...

fmt:
	gofmt -w ./cmd ./aap
