package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nodex/nodex-backend/internal/identity"
	"github.com/nodex/nodex-backend/internal/mailer"
)

const (
	otpLength       = 6
	otpTTL          = 10 * time.Minute
	otpResendAfter  = 60 * time.Second
	otpMaxAttempts  = 5
	sessionTTL      = 15 * time.Minute
	passwordMinLen  = 8
	passwordMaxLen  = 128
	maxEmailLength  = 254
	usernamePattern = `^[A-Za-z0-9_]{3,24}$`
)

var usernameRe = regexp.MustCompile(usernamePattern)

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

type Service struct {
	pool      *pgxpool.Pool
	mailer    mailer.Mailer
	otpSecret []byte
	now       func() time.Time
}

func NewService(pool *pgxpool.Pool, m mailer.Mailer, otpSecret []byte) *Service {
	return &Service{pool: pool, mailer: m, otpSecret: otpSecret, now: time.Now}
}

// RequestOTP emails a fresh one-time code to an email that is not yet registered.
func (s *Service) RequestOTP(ctx context.Context, rawEmail string) error {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return err
	}

	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)`, email).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return newErr(409, "email_taken", "An account with this email already exists.")
	}

	code, err := generateOTP()
	if err != nil {
		return err
	}
	now := s.now()

	// Upsert only if the resend cooldown has passed; otherwise nothing is written.
	var lastSent time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO email_otps (email, code_hash, attempts, expires_at, last_sent_at)
		VALUES ($1, $2, 0, $3, $4)
		ON CONFLICT (email) DO UPDATE
		   SET code_hash = EXCLUDED.code_hash, attempts = 0,
		       expires_at = EXCLUDED.expires_at, last_sent_at = EXCLUDED.last_sent_at
		 WHERE email_otps.last_sent_at <= $5
		RETURNING last_sent_at`,
		email, s.hashOTP(email, code), now.Add(otpTTL), now, now.Add(-otpResendAfter),
	).Scan(&lastSent)
	if errors.Is(err, pgx.ErrNoRows) {
		var prev time.Time
		if err := s.pool.QueryRow(ctx, `SELECT last_sent_at FROM email_otps WHERE email = $1`, email).Scan(&prev); err != nil {
			return err
		}
		e := newErr(429, "otp_cooldown", "Please wait before requesting another code.")
		e.RetryAfter = max(prev.Add(otpResendAfter).Sub(now), time.Second)
		return e
	}
	if err != nil {
		return err
	}

	if err := s.mailer.SendOTP(ctx, email, code, otpTTL); err != nil {
		// Let the user retry immediately instead of waiting out the cooldown.
		s.pool.Exec(ctx, `DELETE FROM email_otps WHERE email = $1`, email)
		return newErr(502, "email_send_failed", "We couldn't send the verification email. Please try again.")
	}
	return nil
}

// VerifyOTP checks the code and, on success, returns a single-use
// registration token bound to the verified email.
func (s *Service) VerifyOTP(ctx context.Context, rawEmail, code string) (string, time.Time, error) {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return "", time.Time{}, err
	}
	code = strings.TrimSpace(code)
	if len(code) != otpLength || strings.Trim(code, "0123456789") != "" {
		return "", time.Time{}, newErr(400, "otp_invalid", "Enter the 6-digit code from your email.")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback(ctx)

	var codeHash []byte
	var attempts int
	var expiresAt time.Time
	err = tx.QueryRow(ctx,
		`SELECT code_hash, attempts, expires_at FROM email_otps WHERE email = $1 FOR UPDATE`, email,
	).Scan(&codeHash, &attempts, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, newErr(400, "otp_expired", "This code has expired. Request a new one.")
	}
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	if now.After(expiresAt) {
		return "", time.Time{}, newErr(400, "otp_expired", "This code has expired. Request a new one.")
	}
	if attempts >= otpMaxAttempts {
		return "", time.Time{}, newErr(429, "otp_locked", "Too many incorrect attempts. Request a new code.")
	}

	if !hmac.Equal(codeHash, s.hashOTP(email, code)) {
		if _, err := tx.Exec(ctx, `UPDATE email_otps SET attempts = attempts + 1 WHERE email = $1`, email); err != nil {
			return "", time.Time{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", time.Time{}, err
		}
		if remaining := otpMaxAttempts - attempts - 1; remaining > 0 {
			return "", time.Time{}, newErr(400, "otp_invalid", fmt.Sprintf("Incorrect code. %d attempt(s) left.", remaining))
		}
		return "", time.Time{}, newErr(429, "otp_locked", "Too many incorrect attempts. Request a new code.")
	}

	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	sessionExpires := now.Add(sessionTTL)
	if _, err := tx.Exec(ctx, `DELETE FROM email_otps WHERE email = $1`, email); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO registration_sessions (token_hash, email, expires_at) VALUES ($1, $2, $3)`,
		hashToken(token), email, sessionExpires,
	); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, err
	}
	return token, sessionExpires, nil
}

func (s *Service) UsernameAvailable(ctx context.Context, username string) (bool, error) {
	if err := validateUsername(username); err != nil {
		return false, err
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) = lower($1))`, username).Scan(&exists)
	return !exists, err
}

type RegisterInput struct {
	RegistrationToken string
	Username          string
	Password          string
	ConfirmPassword   string
	PeerID            string
	PublicKey         []byte
	Signature         []byte
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	PeerID    string    `json:"peer_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Register creates the account for a verified email. The client proves
// ownership of the peer identity by signing identity.RegistrationMessage.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*User, error) {
	if in.RegistrationToken == "" {
		return nil, newErr(401, "session_invalid", "Your verification session has expired. Please verify your email again.")
	}
	if err := validateUsername(in.Username); err != nil {
		return nil, err
	}
	if err := validatePassword(in.Password, in.ConfirmPassword); err != nil {
		return nil, err
	}
	msg := identity.RegistrationMessage(in.Username, in.PeerID, in.RegistrationToken)
	if err := identity.Verify(in.PublicKey, in.PeerID, msg, in.Signature); err != nil {
		return nil, newErr(400, "identity_invalid", "Peer identity verification failed: "+err.Error()+".")
	}

	// Check the session before the (deliberately slow) password hash.
	var email string
	err := s.pool.QueryRow(ctx,
		`SELECT email FROM registration_sessions WHERE token_hash = $1 AND expires_at > $2`,
		hashToken(in.RegistrationToken), s.now(),
	).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, newErr(401, "session_invalid", "Your verification session has expired. Please verify your email again.")
	}
	if err != nil {
		return nil, err
	}

	passwordHash, err := HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Consume the session atomically so a token can only register once.
	var verifiedAt time.Time
	err = tx.QueryRow(ctx,
		`DELETE FROM registration_sessions WHERE token_hash = $1 AND expires_at > $2 RETURNING created_at`,
		hashToken(in.RegistrationToken), s.now(),
	).Scan(&verifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, newErr(401, "session_invalid", "Your verification session has expired. Please verify your email again.")
	}
	if err != nil {
		return nil, err
	}

	u := &User{Email: email, Username: in.Username, PeerID: in.PeerID}
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, email_verified_at, username, password_hash, peer_id, public_key)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at`,
		email, verifiedAt, in.Username, passwordHash, in.PeerID, in.PublicKey,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "users_username_lower_key":
				return nil, newErr(409, "username_taken", "This username is already taken.")
			case "users_email_lower_key":
				return nil, newErr(409, "email_taken", "An account with this email already exists.")
			case "users_peer_id_key":
				return nil, newErr(409, "peer_id_taken", "This Peer ID is already registered. Please try again.")
			}
		}
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// PurgeExpired removes stale OTPs and registration sessions.
func (s *Service) PurgeExpired(ctx context.Context) error {
	now := s.now()
	if _, err := s.pool.Exec(ctx, `DELETE FROM email_otps WHERE expires_at < $1`, now); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM registration_sessions WHERE expires_at < $1`, now)
	return err
}

func (s *Service) hashOTP(email, code string) []byte {
	mac := hmac.New(sha256.New, s.otpSecret)
	mac.Write([]byte(email + ":" + code))
	return mac.Sum(nil)
}

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

func validateUsername(username string) error {
	if !usernameRe.MatchString(username) {
		return newErr(400, "username_invalid", "Username must be 3–24 characters: letters, numbers, or underscores.")
	}
	return nil
}

func validatePassword(password, confirm string) error {
	n := utf8.RuneCountInString(password)
	if n < passwordMinLen || n > passwordMaxLen {
		return newErr(400, "password_invalid", fmt.Sprintf("Password must be %d–%d characters.", passwordMinLen, passwordMaxLen))
	}
	if strings.TrimSpace(password) == "" {
		return newErr(400, "password_invalid", "Password cannot be only whitespace.")
	}
	if password != confirm {
		return newErr(400, "password_mismatch", "Passwords do not match.")
	}
	return nil
}

func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
