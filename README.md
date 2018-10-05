# Current Status

[![CircleCI](https://circleci.com/gh/polyverse/ropoly.svg?style=svg)](https://circleci.com/gh/polyverse/ropoly)

# polyverse/ropoly

## Build Instructions for Ubuntu with Docker
From the project directory, run the following:
$ docker run --rm -it -v $PWD:/go/src/github.com/polyverse/ropoly golang bash
$ cd /go/src/github.com/polyverse/ropoly
$ go build

## Run Instructions for Docker
The container must be run with --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --privileged
Port 8008 must be mapped to a port on the host with -p in order to view output.

## Build Instructions for Alpine with Docker
docker run --rm -it -v $PWD:/go/src/github.com/polyverse/ropoly golang:1.8-alpine /bin/ash
cd /go/src/github.com/polyverse/ropoly
apk add --no-cache make build-base
go build

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

### /api/v1/pid/\<_pid_\>/libraries[?signatures=\<[_true_]\>]
Return list of loaded libraries for the given _pid_. If _pid_ is 0, _pid_ refers to the ROPoly process itself. If signature is _true_, list whether or not each library has a Polyverse signature.

### /api/v1/pid/\<_pid_\>/memory[?mode=\<regions|search|disasm|gadget|fingerprint\>][&start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_][?access=\<[_R_][_W_][_X_][_F_]|_None_\>][?\<string|regexp\>=_target_]
Return information about the memory of the given _pid_ according to the option provided in _mode_.

#### regions
Return list of memory regions of the given _pid_ subject to at least access permissions (default _R_). Any combination of _R_, _W_, _X_ and _F (Windows only)_ is permitted as well as the token _None_ which will return all regions. (Case is not significant.)

#### search
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instances. If string is used, _target_ is the literal string. If regexp is used, _target_ is the regular expression.

#### disasm
Disassemble executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instructions. 

#### gadget
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ gadgets size limited to _instructions_ and _octets_.

### /api/v1/files/\<_path_\>
View information about the files and directories in the given directory on the server according to the option provided in _mode_.

#### directory
View the contents of the given directory. Fails if given a file.

#### signature
Looks for the Polyverse signature, "-PV-", in the given file, and returns based on whether or not it is found. Fails if given a directory.

#### disasm
Disassembles the .text section of the given ELF binary. Fails if given a directory, or if the given file is not an ELF binary.

#### gadget
Search executable memory of the given ELF binary and return up to _limit_ gadgets size limited to _instructions_ and _octets_.