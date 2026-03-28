BIN_DIR := bin
BINARY := $(BIN_DIR)/argus
CMD_PATH := ./cmd/argus

.PHONY: help setup update build run clean

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

clean: ## Remove build artifacts
	@rm -rf $(BIN_DIR)
	@echo "🧹 Cleaned: $(BIN_DIR)"

git: ## Commit + push με προσαρμοσμένο μήνυμα
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push
