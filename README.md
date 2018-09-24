# Current Status

[![CircleCI](https://circleci.com/gh/polyverse/ropoly.svg?style=svg)](https://circleci.com/gh/polyverse/ropoly)

# polyverse/ropoly

## Build Instructions with Docker
From the project directory, run the following:
$ docker run --rm -it -v $PWD:/go/src/github.com/polyverse/ropoly golang bash
$ cd /go/src/github.com/polyverse/ropoly
$ go build

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

### /api/v1/pid/\<_pid_\>/libraries
Return list of loaded libraries for the given _pid_. If _pid_ is 0, _pid_ refers to the ROPoly process itself. Lists whether or not each library has a Polyverse signature.

### /api/v1/pid/\<_pid_\>/memory/regions[?access=\<[_R_][_W_][_X_][_F_]|_None_\>]
Return list of memory regions of the given _pid_ subject to at least access permissions (default _R_). Any combination of _R_, _W_, _X_ and _F (Windows only)_ is permitted as well as the token _None_ which will return all regions. (Case is not significant.)

### /api/v1/pid/\<_pid_\>/memory/search[?\<string|regexp\>=_target_][&start=_start_][&end=_end_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instances. If string is used, _target_ is the literal string. If regexp is used, _target_ is the regular expression.

### /api/v1/pid/\<_pid_\>/memory/disasm[?start=_start_][&end=_end_][&limit=_limit_]
Disassemble executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instructions. 

### /api/v1/pid/\<_pid_\>/memory/gadget[?start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ gadgets size limited to _instructions_ and _octets_. 

### /api/v1/pid/\<_pid_\>/memory/fingerprint[?start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ gadget fingerprints size limited to _instructions_ and _octets_.

### /api/v1/files/\<_path_\>
View information about the files and directories in the given directory on the server.

### /api/v1/is-file-polyverse/\<_path_\>
Check whether or not the given file has a Polyverse signature. If the file does not exist, will only report that the signature is not found; use /files/ endpoint to determine if file exists.