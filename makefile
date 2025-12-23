build:
	go build -o bin/api cmd/api/main.go

run:
	go run cmd/api/main.go

PKGS := $(shell go list ./... | grep -v '/internal/infrastructure/sqlc\|/scripts\|/generated/sqlc\|/vendor')
test-cover:
	go test -v -coverprofile=coverage.out $(PKGS)
	go tool cover -html=coverage.out -o coverage/index.html

.PHONY: test test-unit test-integration test-coverage

test: test-unit test-integration

test-unit:
	@echo "Running unit tests..."
	@go test -v -race -short $(PKGS)

test-integration:
	@echo "Running integration tests..."
	@go test -v -race ./tests/integration/...

test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic $(PKGS)
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

clean:
	rm -rf bin/

migrate:
	go run cmd/migrate/main.go

gen-project:
	go run scripts/gen/main.go

gen-md:
	go run scripts/genMD/main.go

swagger:
	swag init -g cmd/api/main.go --parseDependency --parseInternal -o cmd/api/docs