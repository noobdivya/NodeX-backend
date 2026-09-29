package auth

import (
	"strings"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") || strings.Contains(hash, "correct horse") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if ok, err := VerifyPassword("correct horse battery", hash); err != nil || !ok {
		t.Fatalf("correct password rejected: %v", err)
	}
	if ok, _ := VerifyPassword("wrong password", hash); ok {
		t.Fatal("wrong password accepted")
	}
	other, _ := HashPassword("correct horse battery")
	if other == hash {
		t.Fatal("hashes are not salted")
	}
}

func TestValidation(t *testing.T) {
	for _, u := range []string{"Rahul", "abc", "user_123"} {
		if validateUsername(u) != nil {
			t.Errorf("username %q should be valid", u)
		}
	}
	for _, u := range []string{"", "ab", "has space", "semi;colon", strings.Repeat("a", 25)} {
		if validateUsername(u) == nil {
			t.Errorf("username %q should be invalid", u)
		}
	}
	if _, err := normalizeEmail("  Rahul@Example.COM "); err != nil {
		t.Errorf("valid email rejected: %v", err)
	}
	for _, e := range []string{"", "no-at", "a@b", "Name <a@b.com>", "a@b.com\r\nBcc: x@y.com"} {
		if _, err := normalizeEmail(e); err == nil {
			t.Errorf("email %q should be invalid", e)
		}
	}
	if validatePassword("longenough", "different") == nil {
		t.Error("mismatched passwords accepted")
	}
	if validatePassword("short", "short") == nil {
		t.Error("short password accepted")
	}
}
