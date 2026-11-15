.PHONY: test bench demo fmt vet build

BIN := bin/reinsaarm

build:
	mkdir -p bin
	go build -o $(BIN) ./cmd/reinsaarm

test:
	go test ./...

bench:
	go test ./internal/policy -bench=BenchmarkEvaluate -benchmem -benchtime=200ms -run '^$$'
	go test ./internal/policy -run TestFastPathP99 -v -count=1

demo: build
	bash examples/demo/demo.sh

fmt:
	gofmt -w .

vet:
	go vet ./...
