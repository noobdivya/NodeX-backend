package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/nodex/nodex-backend/internal/config"
)

type Mailer interface {
	SendOTP(ctx context.Context, to, code string, ttl time.Duration) error
}

// New picks how codes are sent: Brevo's API if a key is set, else SMTP,
// else (for local development) printing them to the log.
func New(smtpCfg config.SMTPConfig, brevoAPIKey string) Mailer {
	switch {
	case brevoAPIKey != "":
		return newBrevoMailer(brevoAPIKey, smtpCfg.From)
	case smtpCfg.Enabled():
		return smtpMailer{cfg: smtpCfg}
	default:
		return logMailer{}
	}
}

const otpSubject = "Your NodeX verification code"

func otpBody(code string, ttl time.Duration) string {
	return fmt.Sprintf(
		"Your NodeX verification code is: %s\r\n\r\nIt expires in %d minutes. If you did not request this, you can ignore this email.\r\n",
		code, int(ttl.Minutes()),
	)
}

// otpMessage is the verification email, as an RFC 5322 message.
func otpMessage(from, to, code string, ttl time.Duration) ([]byte, error) {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(from, "\r\n") {
		return nil, fmt.Errorf("invalid address")
	}
	return []byte("From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + otpSubject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + otpBody(code, ttl)), nil
}

// logMailer prints codes to stdout so the flow works locally without SMTP.
type logMailer struct{}

func (logMailer) SendOTP(_ context.Context, to, code string, _ time.Duration) error {
	log.Printf("[dev mailer] OTP for %s: %s", to, code)
	return nil
}

type smtpMailer struct {
	cfg config.SMTPConfig
}

// A blocked or unreachable mail server must fail fast instead of leaving
// the sign-up request hanging.
const (
	dialTimeout = 10 * time.Second
	sendTimeout = 30 * time.Second
)

func (m smtpMailer) SendOTP(ctx context.Context, to, code string, ttl time.Duration) error {
	msg, err := otpMessage(m.cfg.From, to, code, ttl)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}
	from := envelopeAddress(m.cfg.From)

	tlsConfig := &tls.Config{ServerName: m.cfg.Host}
	dialer := &net.Dialer{Timeout: dialTimeout}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var conn net.Conn
	// Port 465 uses implicit TLS; other ports upgrade with STARTTLS.
	if m.cfg.Port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(dialCtx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(sendTimeout)); err != nil {
		conn.Close()
		return err
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if m.cfg.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return err
			}
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// envelopeAddress extracts "a@b" from "Name <a@b>".
func envelopeAddress(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.LastIndex(from, ">"); j > i {
			return from[i+1 : j]
		}
	}
	return from
}
