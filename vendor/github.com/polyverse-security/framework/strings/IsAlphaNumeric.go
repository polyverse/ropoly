package strings

import gostrings "strings"

func IsAlphaNumeric(str string) bool {
	return ContainsOnly(gostrings.ToLower(str), "abcdefghijklmnopqrstuvwxyz0123456789")
}
