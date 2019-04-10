#!/bin/sh

. scripts/.env

VERSION=${1:-master}
GOOS=${2:-linux}

# Directory to house our binaries
mkdir -p bin

# Build the binary in Docker and extract it from the container
docker build --build-arg VERSION=${VERSION} --build-arg GOOS=${GOOS} -t ${DOCKER_REPO}:${VERSION}-${GOOS} ./
docker run --rm --name vault-admin-build -d ${DOCKER_REPO}:${VERSION}-${GOOS} sh -c "sleep 120"
docker cp vault-admin-build:/usr/bin/vadmin bin
docker stop vault-admin-build

# Zip up the binary
cd bin
zip vadmin-${GOOS}-${VERSION}.zip vadmin
rm vadmin
