#!/bin/bash

# This is the build for a static binary on linux
# CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo --ldflags '-extldflags "-static"' .

# This is the build for a dynamic binary on linux
# CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo .

# ... which is approximately equivalent to this on a linux box
CGO_ENABLED=1 GOOS=linux go build .

