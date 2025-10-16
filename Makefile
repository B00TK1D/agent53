# Agent53 Makefile

.PHONY: build test clean run help

# Default target
all: build

# Build the agent53 binary
build:
	@echo "Building agent53..."
	go build -o agent53 main.go
	@echo "Build complete!"

# Run tests
test: build
	@echo "Running DNS server tests..."
	./test.sh

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f agent53
	rm -f dns-server.log
	@echo "Clean complete!"

# Run the server with default config
run: build
	@echo "Starting agent53 DNS server..."
	./agent53

# Run with custom config
run-config: build
	@echo "Starting agent53 with custom config..."
	./agent53 -config config.yaml

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy

# Cross-compile for different platforms
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build -o agent53-linux main.go

build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build -o agent53.exe main.go

build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build -o agent53-darwin main.go

# Build all platforms
build-all: build-linux build-windows build-darwin
	@echo "All platform builds complete!"

# Show help
help:
	@echo "Agent53 Makefile"
	@echo "================"
	@echo ""
	@echo "Available targets:"
	@echo "  build        - Build the agent53 binary"
	@echo "  test         - Run DNS server tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Run the server with default config"
	@echo "  run-config   - Run the server with config.json"
	@echo "  deps         - Install Go dependencies"
	@echo "  build-linux  - Build for Linux"
	@echo "  build-windows- Build for Windows"
	@echo "  build-darwin - Build for macOS"
	@echo "  build-all    - Build for all platforms"
	@echo "  help         - Show this help message"
