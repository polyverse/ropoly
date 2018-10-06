#!/bin/bash

docker cp ropoly $1:/ropoly
docker exec -it --privileged $1 /ropoly
