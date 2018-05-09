#!/bin/sh

VERSION=${1:-master}

docker tag ${DOCKER_REPO}:${VERSION}-linux ${DOCKER_REPO}:${VERSION}
echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin
docker push ${DOCKER_REPO}:${VERSION}
