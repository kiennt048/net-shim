# BEYONDNET Firewall Control - Build Configuration
# Supports cross-compilation from Windows, Linux, or Mac to pfSense (FreeBSD)

# Target: FreeBSD amd64 (pfSense 2.8.1)
GOOS=freebsd
GOARCH=amd64
BINARY_NAME=net-shim

# Version file (stores BASE_VERSION and BUILD_NUM)
VERSION_FILE=.version

# Go build flags
LDFLAGS_BASE=-s -w

.PHONY: all build clean test help windows linux mac version set-version deploy

# Default target
all: build

# Initialize version file if not exists
init-version:
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "1.7.1" > $(VERSION_FILE); \
		echo "0" >> $(VERSION_FILE); \
	fi

# Build for pfSense (FreeBSD amd64)
build: init-version
	@echo "🔨 Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@echo "📁 Current directory: $(shell pwd)"
	@echo "📦 Go module: $(shell go list -m)"
	@# Read current version info and increment build number
	@BASE_VER=$$(head -1 $(VERSION_FILE)); \
	BUILD_NUM=$$(tail -1 $(VERSION_FILE)); \
	BUILD_NUM=$$((BUILD_NUM + 1)); \
	BUILD_TIME=$$(date +%Y%m%d_%H%M); \
	FULL_VERSION="v$$BASE_VER.$$BUILD_NUM"_"$$BUILD_TIME"; \
	echo "📌 Version: $$FULL_VERSION"; \
	echo "$$BASE_VER" > $(VERSION_FILE); \
	echo "$$BUILD_NUM" >> $(VERSION_FILE); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags="-$(LDFLAGS_BASE) -X main.Version=$$BASE_VER -X main.BuildNum=$$BUILD_NUM -X main.BuildTime=$$BUILD_TIME" \
		-o $(BINARY_NAME) .
	@echo "✅ Build complete: $(BINARY_NAME)"
	@echo "📊 Binary size: $(shell ls -lh $(BINARY_NAME) 2>/dev/null | awk '{print $$5}' || echo 'N/A')"
	@NEW_SHA=$$(shasum -a 256 $(BINARY_NAME) | cut -d' ' -f1); \
	sed -i '' "s/EXPECTED_SHA256=\"[a-f0-9]*\"/EXPECTED_SHA256=\"$$NEW_SHA\"/" install.sh && \
	echo "🔐 Updated install.sh SHA256: $$NEW_SHA"
	@echo ""
	@echo "💡 Tip: Uncomment the next line to auto-deploy after builds"
	# @$(MAKE) deploy

# Show current version
version: init-version
	@BASE_VER=$$(head -1 $(VERSION_FILE)); \
	BUILD_NUM=$$(tail -1 $(VERSION_FILE)); \
	NEXT_BUILD=$$((BUILD_NUM + 1)); \
	echo "Current version: v$$BASE_VER.$$BUILD_NUM"; \
	echo "Next build will be: v$$BASE_VER.$$NEXT_BUILD"_"$$(date +%Y%m%d_%H%M)"

# Set new base version: make set-version VERSION=2.10.1
set-version: init-version
	@if [ -z "$(VERSION)" ]; then \
		echo "❌ Usage: make set-version VERSION=2.10.1"; \
		exit 1; \
	fi
	@echo "$(VERSION)" > $(VERSION_FILE)
	@echo "0" >> $(VERSION_FILE)
	@echo "✅ Version set to $(VERSION)"
	@echo "Next build will be: v$(VERSION).1_$$(date +%Y%m%d_%H%M)"

# Quick build shortcuts for local testing (builds for your current OS)
windows:
	@echo "🪟 Building for Windows (testing only - won't work on pfSense)..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-$(LDFLAGS_BASE)" -o $(BINARY_NAME).exe .
	@echo "✅ Windows build complete: $(BINARY_NAME).exe"

linux:
	@echo "🐧 Building for Linux (testing only - won't work on pfSense)..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-$(LDFLAGS_BASE)" -o $(BINARY_NAME)-linux .
	@echo "✅ Linux build complete: $(BINARY_NAME)-linux"

mac:
	@echo "🍎 Building for macOS (testing only - won't work on pfSense)..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-$(LDFLAGS_BASE)" -o $(BINARY_NAME)-mac .
	@echo "✅ macOS build complete: $(BINARY_NAME)-mac"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe $(BINARY_NAME)-linux $(BINARY_NAME)-mac
	@echo "✅ Clean complete"

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Download dependencies
deps:
	@echo "📥 Downloading dependencies..."
	go mod download
	go mod verify
	@echo "✅ Dependencies ready"

# Deploy to GitHub (COMMENTED BY DEFAULT - UNCOMMENT TO ENABLE)
deploy: init-version
	@echo "🚀 Preparing to deploy to GitHub..."
	@# Check if binary exists
	@if [ ! -f $(BINARY_NAME) ]; then \
		echo "❌ Binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@# Read version info
	@BASE_VER=$$(head -1 $(VERSION_FILE)); \
	BUILD_NUM=$$(tail -1 $(VERSION_FILE)); \
	BUILD_TIME=$$(date +%Y%m%d_%H%M); \
	FULL_VERSION="v$$BASE_VER.$$BUILD_NUM"_"$$BUILD_TIME"; \
	TAG_NAME="v$$BASE_VER.$$BUILD_NUM"; \
	SHA256=$$(shasum -a 256 $(BINARY_NAME) | cut -d' ' -f1); \
	echo "📌 Version: $$FULL_VERSION"; \
	echo "🏷️  Tag: $$TAG_NAME"; \
	echo "🔐 SHA256: $$SHA256"; \
	echo ""; \
	echo "⚠️  COMMENTED COMMANDS - Uncomment in Makefile to enable:"; \
	echo "   1. git add net-shim install.sh"; \
	echo "   2. git commit -m \"Release $$FULL_VERSION\""; \
	echo "   3. git tag -a $$TAG_NAME -m \"Build notes...\""; \
	echo "   4. git push origin kientest"; \
	echo "   5. git push origin $$TAG_NAME"; \
	echo ""; \
	echo "🔧 To enable auto-deploy:"; \
	echo "   - Edit Makefile and uncomment the git commands below"; \
	echo ""
	git add $(BINARY_NAME) install.sh
	git commit -m "Release $$FULL_VERSION - Auto-deployed" || echo "⚠️  No changes to commit"
	git tag -a "$$TAG_NAME" -m "Build: $$FULL_VERSION\nSHA256: $$SHA256\nBranch: kientest" -f
	git push origin kientest
	git push origin "$$TAG_NAME" -f
	@echo "✅ Deployed to GitHub: $$TAG_NAME"

# Verify build will work without actually building
verify:
	@echo "🔍 Verifying build configuration..."
	@echo "Go version: $(shell go version)"
	@echo "Module: $(shell go list -m)"
	@echo "Dependencies:"
	@go list -m all
	@echo "✅ Verification complete"

# Show help
help:
	@echo "BEYONDNET Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build                    - Build for pfSense (FreeBSD amd64) [DEFAULT]"
	@echo "  make deploy                   - Deploy to GitHub (git commands commented by default)"
	@echo "  make version                  - Show current version info"
	@echo "  make set-version VERSION=X.Y.Z - Set new base version (resets build to 0)"
	@echo "  make windows                  - Build for Windows (testing only)"
	@echo "  make linux                    - Build for Linux (testing only)"
	@echo "  make mac                      - Build for macOS (testing only)"
	@echo "  make clean                    - Remove build artifacts"
	@echo "  make deps                     - Download dependencies"
	@echo "  make verify                   - Verify build will work"
	@echo "  make test                     - Run tests"
	@echo ""
	@echo "Version Examples:"
	@echo "  make set-version VERSION=2.0.0   # Set to v2.0.0, next build = v2.0.0.1"
	@echo "  make set-version VERSION=2.10.1  # Set to v2.10.1, next build = v2.10.1.1"
	@echo ""
	@echo "Output: $(BINARY_NAME) (FreeBSD binary for pfSense)"
