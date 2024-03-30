#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd $SCRIPT_DIR

#docker build -t filipton/proxied-nginx:latest -f ./nginx.Dockerfile . --push
docker buildx build --push --platform linux/arm64,linux/amd64 -t filipton/proxied-nginx:latest -f ./nginx.Dockerfile .
