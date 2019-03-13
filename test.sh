#!/bin/bash

if [ -z "$(file ropoly | grep " ELF ")" ]; then
	echo "Error: unable to confirm that ropoly is an ELF file."
	exit 1
fi

if [ -z "$(file ropoly32.exe | grep " PE32 ")" ]; then
	echo "error: unable to confirm taht ropoly32.exe is a Win32 executable."
	exit 1
fi

exit 0 
