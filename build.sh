#!/bin/sh

VERSION=0.0.1
GOOS=linux

docker build --build-arg VERSION=${VERSION} --build-arg GOOS=${GOOS} -t readytalk/vault-admin:binary-build ./

docker run --rm --name vault-admin-build -d readytalk/vault-admin:binary-build sh -c "sleep 120"

docker cp vault-admin-build:/usr/bin/vadmin ./
docker stop vault-admin-build

zip vadmin-${VERSION}.zip vadmin
vadmin --version
