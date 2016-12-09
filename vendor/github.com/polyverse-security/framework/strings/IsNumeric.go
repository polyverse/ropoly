package strings

func IsNumeric(str string) bool {
	return ContainsOnly(str, "0123456789")
}
