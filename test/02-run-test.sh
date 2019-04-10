#!/bin/bash

. ../scripts/.env

VAULT_ADDR=http://127.0.0.1:8200

# Get the root token
ROOT_VAULT_TOKEN=$(docker logs vault-test 2>&1 | grep "Root Token:" | sed 's/Root Token: //')
echo "Using token ${ROOT_VAULT_TOKEN}"

# Stop existing stuff if it exists
docker stop vault-admin-test > /dev/null 2>&1
docker rm vault-admin-test > /dev/null 2>&1

# Create out docker network, if it doesn't exist
docker network create vault-admin-test > /dev/null 2>&1

# Run our code
docker run \
  --name vault-admin-test \
  -e VAULT_ADDR=http://vault-test:8200 \
  -e VAULT_TOKEN=${ROOT_VAULT_TOKEN} \
  -e CONFIGURATION_PATH=/config \
  --network vault-admin-test \
  -v $(pwd)/../examples:/config \
  -v $(pwd)/../:/go/src/github.com/PremiereGlobal/vault-admin \
  -w /go/src/github.com/PremiereGlobal/vault-admin \
  golang:1.10.2-alpine go run *.go
