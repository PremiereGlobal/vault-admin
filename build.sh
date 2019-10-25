#!/bin/bash

VERSION=${1:-custom}
GOOS=${2:-linux}

set -e

GO111MODULE=on CGO_ENABLED=0 GOOS=${GOOS} GOARCH=amd64 go build -mod=vendor -ldflags="-s -w -X main.version=${VERSION}" -a -o ./bin/vadmin-${GOOS}

cd bin
cp vadmin-${GOOS} vadmin
zip vadmin-${GOOS}-${VERSION}.zip vadmin
rm vadmin

