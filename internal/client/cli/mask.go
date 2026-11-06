package cli

import "strings"

func maskPassword() string {
	return "********"
}

func maskCardNumber(num string) string {
	if len(num) < 16 {
		return strings.Repeat("*", len(num))
	}
	return num[:4] + "****" + num[len(num)-4:]
}

func maskCVV() string {
	return "***"
}
