#!/bin/bash

set -e

GOVERSION=$(go version)

# code coverage of multiple packages started in go1.10
CANCOVER=$(echo -n $GOVERSION | grep -o 'go1\.[1-9][0-9]' || true)

if [ "$CANCOVER" ]; then
    go test -race -coverprofile=coverage.out ./...
else
    go test -race ./...
fi
