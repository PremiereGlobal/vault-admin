#!/bin/bash

. ../scripts/.env

# Stop existing stuff if it exists
docker stop vault-test > /dev/null 2>&1
docker rm vault-test > /dev/null 2>&1

# Create out docker network, if it doesn't exist
docker network create vault-admin-test > /dev/null 2>&1

# Run a local vault server
docker run \
  --name vault-test \
  -d \
  -p 8200:8200 \
  --network vault-admin-test \
  vault:1.0.1 server -dev

