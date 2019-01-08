package syntax

type RuneFunc func(string) []rune

func DefaultRuneFunc(pattern string) []rune {
	runes := make([]rune, 0, len(pattern))

	//populate our rune array to handle utf8 encoding
	for _, r := range pattern {
		runes = append(runes, r)
	}

	return runes
}

func ByteRuneFunc(pattern string) []rune {
	rawbytes := []byte(pattern)
	runes := make([]rune, len(rawbytes))

	//populate our rune array to handle utf8 encoding
	for index, b := range rawbytes {
		runes[index] = rune(b)
	}

	return runes
}
