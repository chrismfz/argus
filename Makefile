BIN_DIR := bin
SRC_DIR := src
BINARY := $(BIN_DIR)/flowenricher

.PHONY: help setup update build run clean

help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

setup: ## First-time setup after git clone
	cd $(SRC_DIR) && go mod tidy
	@echo "✅ Setup complete."

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	cd $(SRC_DIR) && go list -m -u all | grep -E '\[|\.'
	cd $(SRC_DIR) && go get -u ./...
	cd $(SRC_DIR) && go mod tidy
	@echo "✅ Dependencies updated."

build: ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	cd $(SRC_DIR) && go build \
		-ldflags "-X 'main.Version=$(shell date +%Y.%m.%d)' -X 'main.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)'" \
		-o ../$(BINARY)
	@echo "✅ Built: $(BINARY)"
run: build ## Run the application
	@./$(BINARY)

clean: ## Remove build artifacts
	@rm -rf $(BIN_DIR)
	@echo "🧹 Cleaned: $(BIN_DIR)"
