#!/bin/sh

set -e
set -x

docker build -t golang:mingw32 .
docker run -t --rm -v $PWD:/go/src/github.com/polyverse/ropoly golang:mingw32 bash -c "cd /go/src/github.com/polyverse/ropoly && CC=i686-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=386 go build -o ropoly0.exe"

docker run -t --rm -v $PWD:/go/src/github.com/polyverse/ropoly golang:1.11 bash -c "cd /go/src/github.com/polyverse/ropoly && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ropoly0"

