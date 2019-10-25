#!/bin/bash

VERSION=${1:-master}
if [ "$VERSION" == "master" ]; then
  VERSION="latest"
fi
PUBLISH=${2:-false}

set -e

echo "---------------------"
echo "Building vault-admin"
echo "---------------------"

docker run --rm -v "$PWD":/go/va -w /go/va golang:1.13-alpine \
sh -c "apk add bash zip && ./build.sh ${VERSION} linux"
docker run --rm -v "$PWD":/go/va -w /go/va golang:1.13-alpine \
sh -c "apk add bash zip && ./build.sh ${VERSION} darwin"

echo ""
echo "---------------------"
echo "Building vault-admin Container version: ${VERSION}"
echo "---------------------"

DTAG="premiereglobal/vault-admin:${VERSION}"

docker build . -t ${DTAG}

echo "---------------------"
echo "Created Tag ${DTAG}"
echo "---------------------"

if [[ ${PUBLISH} == "true" && -n $DOCKER_USERNAME && -n $DOCKER_PASSWORD ]]; then
  echo "Pushing docker image: ${DTAG}"
  docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
  docker push ${DTAG}
fi
