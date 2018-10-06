#!/bin/sh

echo "Building Ropoly inside Docker (Alpine)..."

apk update
apk add curl bash alpine-sdk

echo "Installing dep..."
curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

echo "Installing dependencies..."
dep ensure

echo "Building..."
go build

