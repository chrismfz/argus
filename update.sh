#!/bin/bash
set -e

echo "🔍 Checking current dependency versions..."
go list -m -u all | grep -E '\[|\.'

echo "🔄 Updating all dependencies..."
go get github.com/oschwald/geoip2-golang
go get github.com/miekg/dns
go get github.com/ClickHouse/clickhouse-go/v2

go get -u ./...

go mod tidy

echo "✅ Done. Updated dependencies are now:"
go list -m all
