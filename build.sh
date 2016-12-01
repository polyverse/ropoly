#!/bin/bash

REPO=polysploit
BUILDER_SHA=329dc3e5d35a9e4f3644d9f0f0926e477b50d1cb
IMAGE_NAME_BASE=polysploit

echo "$(date) Building binary..."
pv build go
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
  echo "$(date) Failed to build $REPO binary."
  exit $EXIT_CODE
fi

echo "$(date) Obtaining current git sha for tagging the docker image"
headsha=$(git rev-parse --verify HEAD)

echo "--> Git sha is $headsha"
IMAGE_NAME=polyverse/$IMAGE_NAME_BASE:$headsha
echo "--> IMAGE_NAME is $IMAGE_NAME"

echo "$(date) Building a minimal docker image for $IMAGE_NAME_BASE tagged with $headsha..."
docker build -f Dockerfile -t $IMAGE_NAME .
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "$(date) --> Docker build failed."
  exit $EXIT_CODE
fi

docker tag $IMAGE_NAME "polyverse/$IMAGE_NAME_BASE:latest"

echo "$(date) Pushing the new docker image to hub."
docker push $IMAGE_NAME
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
  exit $EXIT_CODE
fi

docker push "polyverse/$IMAGE_NAME_BASE:latest"
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ] ; then
  exit $EXIT_CODE
fi

echo "$(date) Finished."
