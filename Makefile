.PHONY: test test-integration

GOBIN=./build

deps:
	go get -t ./...

test:
	go test -v ./...

test-integration:
	cd integration && go test -v $(TESTARGS)
