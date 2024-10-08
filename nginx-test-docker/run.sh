#!/bin/bash

docker build -t nginx-test-docker .
docker run -it --rm -p 80:80/tcp -p 443:443/tcp -p 1443:443/udp nginx-test-docker
