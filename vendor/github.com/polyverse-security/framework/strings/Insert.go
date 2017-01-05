package strings

import (
	"bytes"
)

// insert substr into str at position pos
func Insert(str string, substr string, pos int) string {
	if len(str) < pos {
		return str
	}

	var buffer bytes.Buffer
	buffer.WriteString(str[:pos])
	buffer.WriteString(substr)
	buffer.WriteString(str[pos:])

	return buffer.String()
}
