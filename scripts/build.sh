#!/bin/sh

. scripts/.env

VERSION=${1:-master}
GOOS=${2:-linux}

# Directory to house our binaries
mkdir -p bin

# Build the binary in Docker and extract it from the container
docker build --no-cache --build-arg VERSION=${VERSION} --build-arg GOOS=${GOOS} -t ${DOCKER_REPO}:${VERSION}-${GOOS} ./
docker run --init --entrypoint sh --rm -v $(pwd)/bin:/mnt ${DOCKER_REPO}:${VERSION}-${GOOS} -c "cp /usr/bin/vadmin /mnt"

# Zip up the binary
cd bin
zip -FS vadmin-${GOOS}-${VERSION}.zip vadmin
rm vadmin
