#!/bin/sh

VERSION=master
GOOS=linux

# Directory to house our binaries
mkdir -p bin

docker build --build-arg VERSION=${VERSION} --build-arg GOOS=${GOOS} -t readytalk/vault-admin:binary-build ./

docker run --rm --name vault-admin-build -d readytalk/vault-admin:binary-build sh -c "sleep 120"

docker cp vault-admin-build:/usr/bin/vadmin bin
docker stop vault-admin-build

zip bin/vadmin-${GOOS}-${VERSION}.zip bin/vadmin
rm bin/vadmin
