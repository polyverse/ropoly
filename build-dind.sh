#!/bin/bash

headsha=$(git rev-parse --verify HEAD)

str="$(cat appdef.js | sed -n 's/^.*"\(.*\/.*:.*\)".*$/\1/p') $(cat images.json | jq -r .[].address) $(cat vfi.json | jq -r .[].address)"

images=( $str )

echo "Making sure images have been pulled..."
for image in "${images[@]}"
do
  echo "--> $image"
  docker pull $image
done
echo

echo "Creating images.tar.gz..."
docker save $str -o images.tar.gz
echo

echo "Building docker images..."
docker build -f Dockerfile.dind -t polyverse/polysploit-dind:$headsha -t polyverse-tools.jfrog.io/polysploit-dind:$headsha -t polyverse/polysploit-dind:latest -t polyverse-tools.jfrog.io/polysploit-dind:latest .
