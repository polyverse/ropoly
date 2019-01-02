package lib

import (
	"os"
	"strings"
)

func EnsureDirectory(path string) error {
	var stack *[]string = new([]string)
	push(stack, strings.TrimSuffix(path, "/"))
	err := windDirectoryStack(stack)
	if err != nil {
		return err
	}
	err = unwindDirectoryStack(stack)
	return err
}

// https://stackoverflow.com/questions/10510691/how-to-check-whether-a-file-or-directory-exists/10510718
func Exists(path string) (bool, error) {
	if path == "" {
		return true, nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func push(stack *[]string, elem string) {
	*stack = append(*stack, elem)
}

func pop(stack *[]string) string {
	ret := peek(stack)
	*stack = (*stack)[:len(*stack)-1]
	return ret
}

func peek(stack *[]string) string {
	return (*stack)[len(*stack)-1]
}

func windDirectoryStack(stack *[]string) error {
	exists := false
	for !exists {
		var err error
		exists, err = Exists(peek(stack))
		if err != nil {
			return err
		}
		if !exists {
			lastSlashIndex := strings.LastIndex(peek(stack), "/")
			if lastSlashIndex == -1 {
				lastSlashIndex = 0
			}
			push(stack, peek(stack)[:lastSlashIndex])
		}
	}
	pop(stack)
	return nil
}

func unwindDirectoryStack(stack *[]string) error {
	for len(*stack) > 0 {
		err := os.Mkdir(pop(stack), os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}
