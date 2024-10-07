#!/bin/bash

docker build -t nginx-test-docker .
docker run -it --rm -p 1443:443/udp nginx-test-docker
