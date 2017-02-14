# polyverse/ropoly

## ROPoly API Endpoints

### /api/v0/pids
Return list of all visible process ids.

### /api/v0/pid/\<_pid_\>/libraries
Return list of loaded libraries for the given _pid_. If_pid_ is 0, _pid_ refers to the introspcetion server process.

### /api/v0/pid/\<_pid_\>memory/safe
Return safe start and end addresses of real code of the given _pid_. Useful to get started with the rest of the API.

### /api/v0/pid/\<_pid_\>memory/regions[?access=\<[_R_][_W_][_X_]|_None_\>]
Return list of memory regions of the given _pid_ subject to at least access permissions (default _R_). Any combination of _R_, _W_ and _X_ is permitted as well as the token _None_ which will return all regions. (Case is not significant.)

### /api/v0/pid/\<_pid_\>/memory/search[[\<string|regexp\>]=_target_][&start=_start_][&end=_end_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instances. If string is used, _target_ is the literal string. If regexp is used, _target_ is the regular expression.

### /api/v0/pid/\<_pid_\>/memory/disasm[start=_start_][&end=_end_][&limit=_limit_]
Disassemble executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ instructions. 

### /api/v0/pid/\<_pid_\>/memory/gadget[start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ gadgets size limited to _instructions_ and _octets_. 

### /api/v0/pid/\<_pid_\>/memory/fingerprint[start=_start_][&end=_end_][&instructions=_instructions_][&octets=_octets_][&limit=_limit_]
Search executable memory of the given _pid_ between _start_ and _end_ and return up to _limit_ gadget fingerprints size limited to _instructions_ and _octets_. 

### /api/v0/pid/\<_pid_\>/memory/overflow?chain=_ropstring_
Performs buffer overflow of the given _pid_ by passing _ropstring_ to an engineered overflow vulnerability. The return address begins after 24 bytes of preamble. (This presently only works for the instropsection server process.)

