package otp

import (
	"net/mail"
	"strings"
)

const maxEmailLength = 254

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	invalid := newErr(400, "email_invalid", "Enter a valid email address.")
	if email == "" || len(email) > maxEmailLength {
		return "", invalid
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", invalid
	}
	at := strings.LastIndexByte(email, '@')
	if at < 1 || !strings.Contains(email[at+1:], ".") {
		return "", invalid
	}
	return email, nil
}
