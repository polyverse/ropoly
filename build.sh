#!/bin/bash

# This is the build for a static binary on linux
# CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo --ldflags '-extldflags "-static"' .

# This is the build for a dynamic binary on linux
# CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo .

# Use pv to build
pv run maketool .
