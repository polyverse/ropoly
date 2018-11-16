# Current Status

[![CircleCI](https://circleci.com/gh/polyverse/ropoly.svg?style=svg)](https://circleci.com/gh/polyverse/ropoly)

# polyverse/ropoly

## Build Instructions
Run "./build.sh"

## Run Instructions for Docker
The container must be run with --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --privileged
Port 8008 must be mapped to a port on the host with -p in order to view output.

## Command Line Options

### server
Runs as a server exposing the API described under "Ropoly API Endpoints." Use this option, "scan", or both.

### scan
Runs as a daemon that repeatedly scans the server's file system and the libraries of its running processes to check for Polyverse signatures. Use this option, "server", or both.

### log
Use only with "scan". Logs the results of scanning for signatures.

### prometheus
Use only with "scan". Not yet implemented, and doesn't do anything useful.

## ROPoly API Endpoints

### /api/v1/pids
Return list of all visible process ids and information about each process.

### /api/v1/pid/\<_pid_\>/libraries[?signatures=\<[true]\>]
Return list of loaded libraries for the given _pid_. If _pid_ is 0, _pid_ refers to the ROPoly process itself. If signature is _true_, list whether or not each library has a Polyverse signature.

### /api/v1/pid/\<_pid_\>[?mode=\<taints|gadgets|fingerprint>][&start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_][?access=\<[_R_][_W_][_X_][_F_]|_None_\>][?\<string|regexp\>=_target_]
Return information about the memory of the given _pid_ according to the option provided in _mode_. _taints_ by default.

### /api/v1/files/\<_path_\>[?query=\<taints|gadgets|fingerprint>][&start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_]
Return information about the files and directories in the given directory on the server according to the option provided in _query_. Default option is _taints_.

### /api/v1/fingerprints
Return the list of fingerprints stored on the server.

### /api/v1/fingerprints/{fingerprint}[?overwrite=true]
Return the contents of the fingerprint with the given name.
Post fingerprint file to add fingerprint with the given name. Fails if fingerprint with given name already exists, unless _overwrite_ is set to true, in which case it will overwrite the old fingerprint.

### /api/v1/fingerprints/{fingerprint}/compare?second=_fingerprint_[&out=_filepath_]
Compares the first given fingerprint to the one provided in _second_. Outputs the generated fingerprint comparison if _out_ is not set. If _out_ is set, saves the fingerprint comparison under the name provided to _out_.

### /api/v1/comparisons
Return the list fingerprint comparisons stored on the server.

### /api/v1/comparisons/{comparison}[?overwrite=true]
Return the contents of the fingerprint comparison with the given name.
Post comparison file to add fingerprint comparison with the given name. Fails if fingerprint with the given name already exists, unless _overwrite_ is set to true, in which case it will overwrite the old comparison.

### /api/v1/comparisons/{comparison}/eqi?func=<|monte-carlo|envisen-original|count-poly|count-exp|>
Calculate the EQI based on the given fingerprint comparison stored on the server, using the EQI function named in _func_. Additional arguments may be required depending on _func_.

### /api/v1/compare?old=_filepath_&new=_filepath_
Recommended to use /api/v1/fingerprints/_old_/compare?second=_new_ instead.
Get fingerprint comparison information about the changes from the _old_/original binary to the _new_/modified binary.

### /api/v1/eqi?comparison=_filepath_&calc=<|monte-carlo|envisen-original|count-poly|count-exp|>
Recommended to use /api/v1/comparisons/_comparison_/eqi instead.
Calculate the EQI based on the given fingerprint comparison file, using the given calculation method. Additional arguments may be required depending on _calc_.

## Query options for /api/v1/pid/<_pid_> and /api/v1/files/<_path_>

### taints
For libraries in memory if looking at a PID or contained files if looking at a directory, check if each is signed by Polyverse.

### gadgets
Find up to _limit_ gadgets between _start_ and _end_ of up to _instructions_ instructions and _octets_ bytes.

### fingerprint
Generate a fingerprint based on up to _limit_ gadgets between _start_ and _end_ of up to _instructions_ instructions and _octets_ bytes. If _out_ is set to a name, saves under that name. Otherwise, outputs to client. Will fail if fingerprint with the given name already exists, unless _overwrite_ is set to true, in which case it will overwrite the old fingerprint.

## EQI options

#### monte-carlo
Uses a Monte Carlo method to simulate _fingerprints_ ROP attacks of length between _min_ and _max_ gadgets. EQI is the percentage of attacks with no common offset.

#### envisen-original
Uses the original formula described at https://github.com/polyverse/EnVisen/blob/master/docs/entropy-index.md as of October 25, 2018.

#### count-poly
Uses a sum-of-squares method based on the number of gadgets weakly surviving at each offset. Uses all offsets for each original gadget by default; set _single_ to true to treat each gadget as having only a single offset. To use a polynomial order other than 2.0, set _order_ to another number.

#### count-exp
Uses the sum of exponents of numbers of gadgets weakly surviving at each offset. Uses all offsets for each original gadget by default; set _single_ to true to treat each gadget as having only a single offset. Default base is 2.0; set _base_ to another value to use a different base.