#!/bin/bash

docker rm -f -v polyverse_supervisor_1
docker rm -f -v $(docker ps -qa)

docker run -d --name=polyverse_supervisor_1 -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/polyverse.yml:/polyverse.yml polyverse/supervisor:3e11e266c5d0c7aeed32f826da53eaece5f9411f -config-yaml-file=/polyverse.yml

watch -n 1 docker ps -a
