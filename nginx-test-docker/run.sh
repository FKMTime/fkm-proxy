#!/bin/bash

docker build -t nginx-test-docker .
docker run -it --rm -p 80:80/tcp -p 443:443/udp -p 443:443/tcp nginx-test-docker
