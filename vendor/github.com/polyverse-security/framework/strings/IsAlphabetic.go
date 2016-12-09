package strings

import gostrings "strings"

func IsAlphabetic(str string) bool {
	return ContainsOnly(gostrings.ToLower(str), "abcdefghijklmnopqrstuvwxyz")
}
