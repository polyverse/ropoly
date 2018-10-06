#!/bin/bash

mkdir bin
docker run --rm -it \
     -v $PWD:/go/src/github.com/polyverse/ropoly \
     -w /go/src/github.com/polyverse/ropoly \
     golang 

echo "Copying libc binary into bin..."
cp ./ropoly ./bin/ropoly-libc-x86_64
