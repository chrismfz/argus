BIN_DIR := bin
BINARY := $(BIN_DIR)/argus
CMD_PATH := ./cmd/argus

# Install destinations. These paths are identical on every systemd + logrotate
# distro (Debian, Ubuntu, RHEL clones such as Rocky/Alma, Fedora, SUSE): local
# unit files live in /etc/systemd/system and logrotate drop-ins in
# /etc/logrotate.d. Override any of them, e.g. for staged packaging:
#   make install DESTDIR=/tmp/stage
DESTDIR       ?=
SYSTEMD_DIR   ?= /etc/systemd/system
LOGROTATE_DIR ?= /etc/logrotate.d
LOG_DIR       ?= /var/log/argus

.PHONY: help setup update build run install clean fmt vet test check lint git

help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

setup: ## First-time setup after git clone
	go mod tidy
	@echo "✅ Setup complete."

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.'
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

build: ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	go build \
		-ldflags "-X 'main.Version=$(shell date +%Y.%m.%d)' -X 'main.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)'" \
		-o $(BINARY) $(CMD_PATH)
	@echo "✅ Built: $(BINARY)"

run: build ## Run the application
	@./$(BINARY)

install: ## Install/refresh systemd unit + logrotate config into place (needs root)
	@if [ "$$(id -u)" -ne 0 ] && [ -z "$(DESTDIR)" ]; then \
		echo "❌ 'make install' writes to /etc — run it as root (sudo make install)"; exit 1; \
	fi
	install -d $(DESTDIR)$(LOG_DIR)
	install -D -m 0644 etc/systemd/system/argus.service $(DESTDIR)$(SYSTEMD_DIR)/argus.service
	@# Canonical drop-in name is 'argus'; remove a stale 'argus-rotate' so the same
	@# logs are not matched by two configs (logrotate warns on duplicate entries).
	@rm -f $(DESTDIR)$(LOGROTATE_DIR)/argus-rotate
	install -D -m 0644 etc/logrotate.d/argus-rotate $(DESTDIR)$(LOGROTATE_DIR)/argus
	@# Live-system steps only — skipped when staging into a DESTDIR.
	@if [ -z "$(DESTDIR)" ]; then command -v systemctl  >/dev/null 2>&1 && systemctl daemon-reload || true; fi
	@if [ -z "$(DESTDIR)" ]; then command -v restorecon >/dev/null 2>&1 && restorecon -F $(SYSTEMD_DIR)/argus.service $(LOG_DIR) 2>/dev/null || true; fi
	@echo "✅ Installed: $(SYSTEMD_DIR)/argus.service + $(LOGROTATE_DIR)/argus"
	@echo "   Apply unit changes: sudo systemctl restart argus"
	@echo "   Test rotation:      logrotate -d $(LOGROTATE_DIR)/argus"

fmt: ## Check formatting (gofmt); fails if any file needs formatting
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "❌ These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "✅ gofmt clean."

vet: ## Run go vet
	go vet ./...
	@echo "✅ go vet clean."

test: ## Run the test suite
	go test ./...

check: vet test ## Run vet + tests (the CI gate)

lint: ## Run golangci-lint if installed (optional, not required by CI)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "⚠️  golangci-lint not installed — skipping. See https://golangci-lint.run"; \
	fi

clean: ## Remove build artifacts
	@rm -rf $(BIN_DIR)
	@echo "🧹 Cleaned: $(BIN_DIR)"

git: ## Commit + push με προσαρμοσμένο μήνυμα
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push
