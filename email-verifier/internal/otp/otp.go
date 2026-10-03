// Package otp is NodeX's only server-side component: a stateless email
// verifier used during registration. It emails a one-time code and checks
// it. It stores no users, keys, contacts, messages or profile data, and has
// no database: the code travels as an HMAC inside a signed token, and the
// only state is short-lived, in-memory anti-abuse data.
package otp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/nodex/nodex-backend/internal/mailer"
)

const (
	codeTTL     = 10 * time.Minute
	resendAfter = 60 * time.Second
	maxAttempts = 5
)

// Error is a client-facing failure with a stable machine-readable code.
type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Message }

func newErr(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

var errExpired = newErr(400, "otp_expired", "This code has expired. Request a new one.")

type Service struct {
	secret []byte
	mailer mailer.Mailer
	now    func() time.Time

	mu       sync.Mutex
	attempts map[string]int       // otp id → failed attempts
	spent    map[string]time.Time // used otp ids → when they'd expire anyway
	lastSent map[string]time.Time // email → last send
}

func NewService(secret []byte, m mailer.Mailer) *Service {
	return &Service{
		secret:   secret,
		mailer:   m,
		now:      time.Now,
		attempts: map[string]int{},
		spent:    map[string]time.Time{},
		lastSent: map[string]time.Time{},
	}
}

type tokenPayload struct {
	ID      string `json:"id"`
	Email   string `json:"e"`
	Expires int64  `json:"x"`
	CodeMAC string `json:"c"`
}

// Send emails a new code and returns a signed token that carries (only a MAC
// of) the code, so nothing needs to be stored.
func (s *Service) Send(ctx context.Context, rawEmail string) (token string, err error) {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return "", err
	}
	now := s.now()

	s.mu.Lock()
	if last, ok := s.lastSent[email]; ok && now.Sub(last) < resendAfter {
		s.mu.Unlock()
		e := newErr(429, "otp_cooldown", "Please wait before requesting another code.")
		e.RetryAfter = max(resendAfter-now.Sub(last), time.Second)
		return "", e
	}
	s.lastSent[email] = now
	s.mu.Unlock()

	code, err := randomCode()
	if err != nil {
		return "", err
	}
	id := randomID()
	token, err = s.sign(tokenPayload{ID: id, Email: email, Expires: now.Add(codeTTL).Unix(), CodeMAC: s.codeMAC(id, email, code)})
	if err != nil {
		return "", err
	}

	if err := s.mailer.SendOTP(ctx, email, code, codeTTL); err != nil {
		s.mu.Lock()
		delete(s.lastSent, email) // let the user retry immediately
		s.mu.Unlock()
		return "", newErr(502, "email_send_failed", "We couldn't send the verification email. Please try again.")
	}
	return token, nil
}

// Verify checks a code against its token. Each code can be used once.
func (s *Service) Verify(otpToken, code string) error {
	p, err := s.parse(otpToken)
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return newErr(400, "otp_invalid", "Enter the 6-digit code from your email.")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.spent[p.ID]; used {
		return errExpired
	}
	if s.attempts[p.ID] >= maxAttempts {
		return newErr(429, "otp_locked", "Too many incorrect attempts. Request a new code.")
	}
	if !hmac.Equal([]byte(p.CodeMAC), []byte(s.codeMAC(p.ID, p.Email, code))) {
		s.attempts[p.ID]++
		if left := maxAttempts - s.attempts[p.ID]; left > 0 {
			return newErr(400, "otp_invalid", fmt.Sprintf("Incorrect code. %d attempt(s) left.", left))
		}
		return newErr(429, "otp_locked", "Too many incorrect attempts. Request a new code.")
	}
	s.spent[p.ID] = time.Unix(p.Expires, 0)
	delete(s.attempts, p.ID)
	return nil
}

// Purge drops anti-abuse state that has outlived its tokens.
func (s *Service) Purge() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, exp := range s.spent {
		if now.After(exp) {
			delete(s.spent, id)
		}
	}
	for email, t := range s.lastSent {
		if now.Sub(t) > resendAfter {
			delete(s.lastSent, email)
		}
	}
	if len(s.attempts) > 100_000 { // bounded; ids expire with their tokens
		s.attempts = map[string]int{}
	}
}

func (s *Service) codeMAC(id, email, code string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("code|" + id + "|" + email + "|" + code))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Service) sign(p tokenPayload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + s.mac(body), nil
}

func (s *Service) mac(body string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("token|" + body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Service) parse(token string) (*tokenPayload, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.mac(body))) {
		return nil, errExpired
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, errExpired
	}
	var p tokenPayload
	if err := json.Unmarshal(b, &p); err != nil || p.ID == "" {
		return nil, errExpired
	}
	if s.now().Unix() > p.Expires {
		return nil, errExpired
	}
	return &p, nil
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
