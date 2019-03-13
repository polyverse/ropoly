package handlers

import "strings"

func NormalizePath(rawPath string) string {
	return strings.Replace(rawPath, "%20", " ", -1)
}