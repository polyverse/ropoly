#!/bin/bash

set -e

# exit without doing anything if this is a travis pull request
if [ "$TRAVIS_PULL_REQUEST" != "false" ] && [ ! -z "$TRAVIS_PULL_REQUEST" ]; then
	exit 0
fi

# if this is being run in travis, the TRAVIS_COMMIT will be the value of the git commit
GIT_COMMIT=$TRAVIS_COMMIT

if [ -z "$GIT_COMMIT" ]; then
	GIT_COMMIT=$(git rev-parse --verify HEAD)
fi

if [ -z "$GIT_COMMIT" ]; then
	echo "Error: GIT_COMMIT variable is empty."
	exit 1
fi

GIT_SHORTSHA="${GIT_COMMIT:0:7}"

tar -cvf ropoly-$GIT_SHORTSHA.tar ropoly ropoly32.exe

# Publish the tarball on S3:
aws s3 cp ropoly-$GIT_SHORTSHA.tar s3://$PV_S3_BUCKET/public/ropoly-${GIT_SHORTSHA}.tar
if [ $? -ne 0 ]; then
	echo "Error: aws s3 cp command returned non-zero."
	exit 1
fi


echo
echo "Install command:"
echo
echo "  curl https://dl.polyverse.io/ropoly-$GIT_SHORTSHA.tar | tar -xvf - -C /c/"
echo

exit 0
