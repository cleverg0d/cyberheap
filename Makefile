.PHONY: build test vet fmt fmtcheck check run clean

BIN := cyberheap
PKG := ./...

build:
	go build -o bin/$(BIN) ./cmd/cyberheap

test:
	go test $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w .

fmtcheck:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt issues:"; echo "$$out"; exit 1; fi

check: fmtcheck vet test

run: build
	./bin/$(BIN)

clean:
	rm -rf bin
