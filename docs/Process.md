# Getting an EQI

## Step 1: Binaries to fingerprints

### If you haven't generated the fingerprints yet, or if you aren't sure what to do

For each binary (original and modified), do a GET request on localhost:8008/api/v1/_path/to/file_?query=fingerprint&out=_name_. The name for each fingerprint should be different. If a fingerprint of either chosen name is already stored on the server, you need to use "&overwrite=true" (this will overwrite any existing fingerprint with that name). If you want to change the maximum length in instructions of the gadgets making up the fingerprint from the default, use "&len=_length_". Ropoly will generate and store the fingerprint under the chosen name.

### If the fingerprints already exist, but are not stored by Ropoly

Post each fingerprint to localhost:8008/api/v1/fingerprints/_name_. Choose a different name for each fingerprint. If the name is already used for an existing fingerprint stored by Ropoly, you must use "&overwrite=true". This will overwrite any fingerprint already stored by Ropoly under that name.

### If you previously generated the fingerprints and stored them in Ropoly

Go to step 2.

## Step 2: Fingerprints to EQI

Do a GET request on localhost:8008/api/v1/fingerprints/_originalFingerprintName_/eqi?second=_modifiedFingerprintName_\&func=_eqiFunction_. The output is the EQI as a string. All EQI functions you can choose from are described in the README. The current standard is the EnVisen method, _envisen-original_. If you want to read why I think you shouldn't use that method and what I think you should use instead, please see https://github.com/polyverse/ropoly/blob/master/docs/EQIFunctions.md .