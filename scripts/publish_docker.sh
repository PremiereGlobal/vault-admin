#!/bin/sh

SOURCE_VERSION=${1:-master}
PUBLISH_VERSION=${2:-$SOURCE_VERSION}

docker tag ${DOCKER_REPO}:${SOURCE_VERSION}-linux ${DOCKER_REPO}:${PUBLISH_VERSION}
echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin
docker push ${DOCKER_REPO}:${PUBLISH_VERSION}
