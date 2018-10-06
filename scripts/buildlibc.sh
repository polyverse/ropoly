#!/bin/bash

echo "Building Ropoly inside Docker..."

echo "Installing dep..."
curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

echo "Installing dependencies..."
dep ensure

echo "Building..."
go build

