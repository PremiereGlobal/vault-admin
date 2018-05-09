#!/bin/sh

VERSION=${1:-master}
GOOS=${2:-linux}

# Directory to house our binaries
mkdir -p bin

docker build --build-arg VERSION=${VERSION} --build-arg GOOS=${GOOS} -t ${DOCKER_REPO}:${VERSION}-${GOOS} ./

docker run --rm --name vault-admin-build -d ${DOCKER_REPO}:${VERSION}-${GOOS} sh -c "sleep 120"

docker cp vault-admin-build:/usr/bin/vadmin bin
docker stop vault-admin-build

zip bin/vadmin-${GOOS}-${VERSION}.zip bin/vadmin
rm bin/vadmin
