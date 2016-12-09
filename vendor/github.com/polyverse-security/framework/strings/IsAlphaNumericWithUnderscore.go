package strings

import gostrings "strings"

func IsAlphaNumericWithUnderscore(str string) bool {
	return ContainsOnly(gostrings.ToLower(str), "abcdefghijklmnopqrstuvwxyz0123456789_")
}
