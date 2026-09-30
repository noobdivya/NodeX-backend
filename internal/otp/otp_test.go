package otp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type captureMailer struct{ code string }

func (m *captureMailer) SendOTP(_ context.Context, _, code string, _ time.Duration) error {
	m.code = code
	return nil
}

func newTestService(t *testing.T) (*Service, *captureMailer, *time.Time) {
	t.Helper()
	m := &captureMailer{}
	secret := make([]byte, 32)
	rand.Read(secret)
	s := NewService(secret, m)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s, m, &now
}

func code(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	return e.Code
}

func TestSendAndVerify(t *testing.T) {
	s, m, _ := newTestService(t)
	tok, err := s.Send(context.Background(), " Rahul@Example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tok, m.code) {
		t.Fatal("token must not contain the code")
	}
	if err := s.Verify(tok, m.code); err != nil {
		t.Fatalf("correct code rejected: %v", err)
	}
	// Single use.
	if err := s.Verify(tok, m.code); code(t, err) != "otp_expired" {
		t.Errorf("code reuse: %v", err)
	}
}

func TestWrongCodeLocksAfterFiveAttempts(t *testing.T) {
	s, m, _ := newTestService(t)
	tok, _ := s.Send(context.Background(), "a@b.co")
	wrong := "000000"
	if m.code == wrong {
		wrong = "111111"
	}
	for i := 1; i <= 4; i++ {
		if err := s.Verify(tok, wrong); code(t, err) != "otp_invalid" {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := s.Verify(tok, wrong); code(t, err) != "otp_locked" {
		t.Fatalf("5th attempt should lock: %v", err)
	}
	if err := s.Verify(tok, m.code); code(t, err) != "otp_locked" {
		t.Fatalf("correct code after lock must fail: %v", err)
	}
}

func TestTamperExpiryAndCooldown(t *testing.T) {
	s, m, now := newTestService(t)
	tok, _ := s.Send(context.Background(), "a@b.co")

	if _, err := s.Send(context.Background(), "a@b.co"); code(t, err) != "otp_cooldown" {
		t.Errorf("cooldown: %v", err)
	}

	// Changing the email inside the token breaks its signature.
	body, sig, _ := strings.Cut(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	forged := strings.Replace(string(raw), "a@b.co", "x@y.co", 1)
	if err := s.Verify(base64.RawURLEncoding.EncodeToString([]byte(forged))+"."+sig, m.code); code(t, err) != "otp_expired" {
		t.Errorf("tampered token accepted: %v", err)
	}

	*now = now.Add(codeTTL + time.Second)
	if err := s.Verify(tok, m.code); code(t, err) != "otp_expired" {
		t.Errorf("expired token accepted: %v", err)
	}
}
