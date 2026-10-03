package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const brevoSendURL = "https://api.brevo.com/v3/smtp/email"

// brevoMailer sends through Brevo's transactional email API over HTTPS
// (port 443), for hosts that block outgoing SMTP. The sender address must
// be verified in the Brevo account.
type brevoMailer struct {
	apiKey    string
	fromName  string
	fromEmail string
	client    *http.Client
	sendURL   string
}

func newBrevoMailer(apiKey, from string) *brevoMailer {
	return &brevoMailer{
		apiKey:    apiKey,
		fromName:  displayName(from),
		fromEmail: envelopeAddress(from),
		client:    &http.Client{Timeout: sendTimeout},
		sendURL:   brevoSendURL,
	}
}

type brevoAddress struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

func (m *brevoMailer) SendOTP(ctx context.Context, to, code string, ttl time.Duration) error {
	if strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("invalid address")
	}
	payload, err := json.Marshal(map[string]any{
		"sender":      brevoAddress{Name: m.fromName, Email: m.fromEmail},
		"to":          []brevoAddress{{Email: to}},
		"subject":     otpSubject,
		"textContent": otpBody(code, ttl),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.sendURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("api-key", m.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("brevo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Brevo explains the problem in the body, e.g. an unverified sender,
		// an invalid key, or an IP address that isn't authorised.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("brevo: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

// displayName extracts "Name" from "Name <a@b>" (empty if there is none).
func displayName(from string) string {
	if i := strings.LastIndex(from, "<"); i > 0 {
		return strings.Trim(strings.TrimSpace(from[:i]), `"`)
	}
	return ""
}
