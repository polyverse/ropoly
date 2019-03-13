#!/bin/bash

set -e
set -x

# if this is being run in travis, the TRAVIS_COMMIT will be the value of the git commit
GIT_COMMIT=$TRAVIS_COMMIT

if [ -z "$GIT_COMMIT" ]; then
	GIT_COMMIT=$(git rev-parse --verify HEAD)
fi

if [ -z "$GIT_COMMIT" ]; then
	echo "Error: GIT_COMMIT variable is empty."
	exit 1
fi

tar -zcvf ropoly-$GIT_COMMIT.tar.gz ropoly ropoly32.exe

# Publish the tarball on S3:
#aws s3 cp ropoly-$GIT_COMMIT.tar.gz s3://$PV_S3_BUCKET/ropoly-${GIT_COMMIT}.tar.gz
#if [ $? -ne 0 ]; then
#	echo "Error: aws s3 cp command returned non-zero."
#	exit 1
#fi

exit 0
