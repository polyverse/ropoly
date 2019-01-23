#!/usr/bin/env bash
test_pair() {
	local input="$1"
	local expected="$2"
	output=$(curl localhost:8008/api/v1/$input)
	if [[ ! "$output" == "$expected" ]]
	then
		echo "Expected $expected"
		echo "Got $output"
		exit
	fi
}

# health
test_pair health "\"Ropoly API Healthy\""

# fingerprint POST and GET
curl -F fingerprint=@TestFiles/fingerprint localhost:8008/api/v1/fingerprints/uploadtest?overwrite=true
test_pair fingerprints/uploadtest "$(cat TestFiles/fingerprint)"

# eqi
curl -F fingerprint=@TestFiles/original localhost:8008/api/v1/fingerprints/original?overwrite=true
curl -F fingerprint=@TestFiles/aslr localhost:8008/api/v1/fingerprints/aslr?overwrite=true
curl -F fingerprint=@TestFiles/eqi50 localhost:8008/api/v1/fingerprints/eqi50?overwrite=true
curl -F fingerprint=@TestFiles/eqi90 localhost:8008/api/v1/fingerprints/eqi90?overwrite=true
curl -F fingerprint=@TestFiles/allDead localhost:8008/api/v1/fingerprints/allDead?overwrite=true
test_pair fingerprints/original/eqi?func=shared-offsets\&second=original 0
test_pair fingerprints/original/eqi?func=shared-offsets\&second=aslr 0
test_pair fingerprints/original/eqi?func=shared-offsets\&second=eqi50 50
test_pair fingerprints/original/eqi?func=shared-offsets\&second=eqi90 90
test_pair fingerprints/original/eqi?func=shared-offsets\&second=allDead 100

# compare
test_pair fingerprints/original/compare?second=allDead "$(cat TestFiles/allDeadComparison)"

# uploadedfiles POST and GET
curl -F file=@TestFiles/loop localhost:8008/api/v1/uploadedfiles/loop?overwrite=true
test_pair uploadedfiles/loop false

# loop fingerprint should be identical to test fingerprint
test_pair uploadedfiles/loop?query=fingerprint "$(cat TestFiles/fingerprint)"

# Should still be identical if we save and then cat
curl localhost:8008/api/v1/uploadedfiles/loop?query=fingerprint\&out=loop\&overwrite=true
test_pair fingerprints/loop "$(cat TestFiles/fingerprint)"

echo "All tests passed"