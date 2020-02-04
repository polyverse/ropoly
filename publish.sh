#!/bin/bash
set -e

declare -r PV_DOCKER_REGISTRY="507760724064.dkr.ecr.us-west-2.amazonaws.com"
declare -r GIT_COMMIT="$(git rev-parse --verify HEAD)"

main() {
        aws --region us-west-2 ecr get-login --no-include-email | bash -s
        [ $? -ne 0 ] && return 1

	publishTarball
        [ $? -ne 0 ] && return 1

	return 0
}

publishTarball() {
	aws s3 cp shadow.tar s3://polyverse-artifacts/ropoly/ropoly0
        [ $? -ne 0 ] && return 1

	aws s3 cp shadow.tar s3://polyverse-artifacts/ropoly/ropoly0-${GIT_COMMIT}
        [ $? -ne 0 ] && return 1

	aws s3 cp shadow.tar s3://polyverse-artifacts/ropoly/ropoly0.exe
        [ $? -ne 0 ] && return 1

	aws s3 cp shadow.tar s3://polyverse-artifacts/ropoly/ropoly0.exe-${GIT_COMMIT}
        [ $? -ne 0 ] && return 1

	return 0
}

main "$@"
exit $?
