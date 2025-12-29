build:
	go build -o bin/api cmd/api/main.go

run:
	go run cmd/api/main.go

PKGS := $(shell go list ./... | grep -v '/internal/infrastructure/sqlc\|/scripts\|/generated/sqlc\|/vendor')
test-cover:
	go test -v -coverprofile=coverage.out $(PKGS)
	go tool cover -html=coverage.out -o coverage.html


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

# Migration commands
mg-create:
	@echo "Creating migration: $(name)"
	go run cmd/migrate/main.go create $(name) sql

mg-up:
	@echo "Applying all migrations"
	go run cmd/migrate/main.go up

mg-up-by-one:
	@echo "Applying one migration"
	go run cmd/migrate/main.go up-by-one

mg-down:
	@echo "Rolling back last migration"
	go run cmd/migrate/main.go down

mg-reset:
	@echo "Resetting all migrations"
	go run cmd/migrate/main.go reset

mg-status:
	@echo "Migration status:"
	go run cmd/migrate/main.go status

mg-version:
	@echo "Current migration version:"
	go run cmd/migrate/main.go version

mg-test-db:
	@echo "Running migrations on test database"
	go run cmd/migrate/main.go up test
