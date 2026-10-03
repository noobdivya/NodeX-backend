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

func New(cfg config.SMTPConfig) Mailer {
	if !cfg.Enabled() {
		return logMailer{}
	}
	return smtpMailer{cfg: cfg}
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

func (m smtpMailer) SendOTP(_ context.Context, to, code string, ttl time.Duration) error {
	if strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("invalid recipient")
	}
	body := fmt.Sprintf(
		"Your NodeX verification code is: %s\r\n\r\nIt expires in %d minutes. If you did not request this, you can ignore this email.\r\n",
		code, int(ttl.Minutes()),
	)
	msg := "From: " + m.cfg.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: Your NodeX verification code\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body

	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}
	from := envelopeAddress(m.cfg.From)

	// Port 465 uses implicit TLS; everything else goes through SendMail,
	// which upgrades with STARTTLS when the server offers it.
	if m.cfg.Port != 465 {
		return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: m.cfg.Host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
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
	if _, err := w.Write([]byte(msg)); err != nil {
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
