package strings

import (
	gostrings "strings"
)

/**
This function is a more specific form of of the classic "string.Contains"

While string.Contains finds whether a string contains any of the characters
specified in the chars list, this function finds whether a string consists
ONLY of those characters in the chars list, and nothing else.

This allows us to check for not ony containment, but exclusion of characters
not explicitly whitelisted.

This is very useful when you want to validate a string is hexadecimal, alphanumeric,
or contains only particular characters.
*/
func ContainsOnly(str string, chars string) bool {
	for _, c := range str {
		if !gostrings.ContainsRune(chars, c) {
			return false
		}
	}

	return true
}
