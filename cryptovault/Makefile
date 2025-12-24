
.PHONY: all build test clean install run-demo coverage lint

# Build variables
BINARY_NAME=cryptovault
BUILD_DIR=./build
CMD_DIR=./cmd/cryptovault

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GORUN=$(GOCMD) run

all: test build

build:
	@echo "Building CryptoVault..."
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

install:
	@echo "Installing dependencies..."
	$(GOGET) github.com/spf13/cobra@latest
	$(GOGET) github.com/spf13/viper@latest
	$(GOGET) golang.org/x/crypto@latest
	$(GOGET) github.com/pquerna/otp@latest
	$(GOGET) github.com/skip2/go-qrcode@latest
	$(GOGET) github.com/stretchr/testify@latest
	$(GOMOD) tidy
	@echo "Dependencies installed"

test:
	@echo "Running tests..."
	$(GOTEST) -v ./test/...
	@echo "Tests complete"

coverage:
	@echo "Generating coverage report..."
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint:
	@echo "Running linters..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Installing golangci-lint..."; go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; }
	golangci-lint run ./...

clean:
	@echo "Cleaning..."
	$(GOCMD) clean
	rm -rf $(BUILD_DIR)
	rm -rf ./data
	rm -rf ./test_data*
	rm -f coverage.out coverage.html
	@echo "Clean complete"

run-demo:
	@echo "Running demo..."
	@mkdir -p ./demo_data
	@echo "\n=== Registering Alice ==="
	$(GORUN) $(CMD_DIR) --datadir ./demo_data auth register -u alice -p "AlicePass123!"
	@echo "\n=== Registering Bob ==="
	$(GORUN) $(CMD_DIR) --datadir ./demo_data auth register -u bob -p "BobPass456!"
	@echo "\n=== Mining Block ==="
	$(GORUN) $(CMD_DIR) --datadir ./demo_data blockchain mine
	@echo "\n=== Viewing Blockchain ==="
	$(GORUN) $(CMD_DIR) --datadir ./demo_data blockchain view
	@echo "\nDemo complete! Check ./demo_data directory"

# Development helpers
dev-setup: install
	@echo "Setting up development environment..."
	@mkdir -p data/{users,keys,messages,blockchain}
	@echo "Development environment ready"

fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

vet:
	@echo "Vetting code..."
	$(GOCMD) vet ./...

# Docker build (bonus)
docker-build:
	docker build -t cryptovault:latest .

docker-run:
	docker run -it --rm -v $(PWD)/data:/app/data cryptovault:latest