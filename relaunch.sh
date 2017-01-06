#!/bin/bash

docker rm -f -v polyverse_supervisor_1
docker rm -f -v $(docker ps -qa)
docker rm -f -v $(docker ps -qa)

docker build -t polyverse-tools.jfrog.io/polysploit .

docker run -e DOCKER_API_VERSION=1.24 -d --name=polyverse_supervisor_1 -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/polyverse.yml:/polyverse.yml polyverse-runtime.jfrog.io/supervisor:8181674177f0c9e57056517c426374a104bc580a -config-yaml-file=/polyverse.yml

watch -n 1 docker ps -a
