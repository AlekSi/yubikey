all: install test

help:                                      ## Display this help message
	@echo "Please use \`make <target>\` where <target> is one of:"
	@grep '^[a-zA-Z]' $(MAKEFILE_LIST) | \
		awk -F ':.*?## ' 'NF==2 {printf "  %-26s%s\n", $$1, $$2}'

init:                                      ## Install development tools
	go mod tidy -v
	cd tools && go mod tidy -v && go generate -x -tags=tools

bin/golangci-lint:
	$(MAKE) init

install:
	go install -v -race ./...

test: install
	go test -race ./...

lint: bin/golangci-lint
	bin/golangci-lint run --config=.golangci-required.yml
	bin/golangci-lint run --config=.golangci.yml
