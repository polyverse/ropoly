# Introduction

Ropoly can be used to compare the attack surfaces of binaries--both binary files and processes loaded in memory.

To use Ropoly to compare two binaries, first take a fingerprint of each binary, and store them on the Ropoly server.

Once you have two binaries, you can use one of Ropoly's methods to compare them.

This document describes some of the ways that you can generate and compare fingerprints. Please see README.md for a complete list of options.

# Fingerprints

## Fingerprint of a process

Use /api/v1/pids/\<_pid_\>?query=fingerprint

Replace \<_pid_\> with the PID of the process you want to fingerprint. You can use 0 to fingerprint the Ropoly server.

This will output a fingerprint of the process, but will not save the fingerprint.

## Fingerprint of a file

Use /api/v1/files/\<_path/to/file_\>?query=fingerprint

Replace \<_path/to/file_\> with the absolute filepath. On Windows, the file must be on C:, and "C:" must be omitted from the filepath.

This will output a fingerprint of the file, but will not save the fingerprint.

## Saving a fingerprint

When fingerprinting a process or a file, you can save it to the Ropoly server instead of outputting the fingerprint by adding &out=<_name_> to the end of the URI. This can be done when fingerprinting a process or a file.

Replace \<_name_\> with the name that you want to save the fingerprint under. You will be able to access the fingerprint using this name.

If a fingerprint is already saved as \<_name_\>, this will fail and output a message. To overwrite the existing file, add &overwrite=true to the end of the URI.

Example: /api/v1/pids/0?query=fingerprint&out=f1&overwrite=true

# Comparisons

## Gadget survival \("strong survival"\)

To find the fraction of gadgets from one fingerprint \(the "first" fingerprint\) that no longer exist at the same address in another fingerprint \(the "second" fingerprint\), use /api/v1/fingerprints/\<_first_\>/survival?second=\<_second_\>

Replace \<_first_\> with the name the first fingerprint was saved under and \<_second_\> with the name the second fingerprint was saved under.

The result will be outputted as a decimal.

## EQI

EQI is defined as a score between 0 and 100 of how well the attack surfaces of two binaries differ, 0 being the most similar and 100 being completely different. Unlike gadget survival, EQI accounts for patterns of gadget movement. For example, a scrambled binary in which each of 10 gadgets move by a different offset should have a higher EQI compared to the original than one in which all 10 of those gadgets move +5 bytes. A goal of a scrambled binary produced by Polyverse is to produce a high EQI with the first fingerprint taken from the official binary and the second fingerprint taken from the scrambled binary.

Ropoly supports several candidate EQI measures. For descriptions of each, please see README.md.

To get the EQI of a fingerprint "f1" compared to a fingerprint "f2", assuming that both fingerprints are saved under those names, use /api/v1/fingerprints/f1/eqi?second=f2&func=shared-offsets

You can replace "shared-offsets" with any other supported EQI function.