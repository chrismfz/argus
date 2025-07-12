#!/bin/bash
set -e

echo "🔍 Checking current dependency versions..."
go list -m -u all | grep -E '\[|\.'

echo "🔄 Updating all dependencies..."
go get -u ./...
go mod tidy

echo "✅ Done. Updated dependencies are now:"
go list -m all
