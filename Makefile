include Makefile.mk

REGISTRY_HOST=docker.io
USERNAME=$(USER)
NAME=$(shell basename $(CURDIR))

format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test ./... -cover

.PHONY: format test
