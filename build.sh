#!/bin/bash

mkdir bin

docker run --rm -it \
     -v $PWD:/go/src/github.com/polyverse/ropoly \
     -w /go/src/github.com/polyverse/ropoly \
     golang scripts/buildlibc.sh

echo "Copying libc binary into bin..."
cp ./ropoly ./bin/ropoly-libc-x86_64

docker run --rm -it \
     -v $PWD:/go/src/github.com/polyverse/ropoly \
     -w /go/src/github.com/polyverse/ropoly \
     golang:alpine scripts/buildmusl.sh

echo "Copying musl binary into bin..."
cp ./ropoly ./bin/ropoly-musl-x86_64
