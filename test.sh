#!/usr/bin/env bash
test_pair() {
	local input="$1"
	local expected="$2"
	output=$(curl localhost:8008/api/v1/$1)
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

echo "All tests passed"