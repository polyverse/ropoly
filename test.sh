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

test_pair "health" "\"Ropoly API Healthy\""

curl -F "fingerprint=@TestFiles/fingerprint" localhost:8008/api/v1/fingerprints/uploadtest?overwrite=true
test_pair "fingerprints/uploadtest" "$(cat TestFiles/fingerprint)"

echo "All tests passed"