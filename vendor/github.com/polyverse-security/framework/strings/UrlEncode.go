package strings

import "net/url"

func UrlEncode(str string) string {
	u := url.URL{Path: str}
	return u.String()
}
