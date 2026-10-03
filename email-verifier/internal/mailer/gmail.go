package mailer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nodex/nodex-backend/internal/config"
)

// GmailSendScope is the only permission requested: send mail as the
// account. It can't read, change or delete anything in the mailbox.
const GmailSendScope = "https://www.googleapis.com/auth/gmail.send"

const (
	googleTokenURL = "https://oauth2.googleapis.com/token"
	gmailSendURL   = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
)

// gmailMailer sends through the Gmail API over HTTPS (port 443), for hosts
// that block outgoing SMTP. It exchanges the stored refresh token for a
// short-lived access token and reuses it until it nearly expires.
type gmailMailer struct {
	cfg      config.GmailConfig
	from     string
	client   *http.Client
	tokenURL string
	sendURL  string

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newGmailMailer(cfg config.GmailConfig, from string) *gmailMailer {
	return &gmailMailer{
		cfg:      cfg,
		from:     from,
		client:   &http.Client{Timeout: sendTimeout},
		tokenURL: googleTokenURL,
		sendURL:  gmailSendURL,
	}
}

func (m *gmailMailer) SendOTP(ctx context.Context, to, code string, ttl time.Duration) error {
	msg, err := otpMessage(m.from, to, code, ttl)
	if err != nil {
		return err
	}
	token, err := m.accessToken(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"raw": base64.RawURLEncoding.EncodeToString(msg)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.sendURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("gmail send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusUnauthorized {
			m.forgetToken()
		}
		return fmt.Errorf("gmail send: %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

func (m *gmailMailer) forgetToken() {
	m.mu.Lock()
	m.token = ""
	m.mu.Unlock()
}

// accessToken returns a valid access token, refreshing it when needed.
func (m *gmailMailer) accessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != "" && time.Until(m.expires) > time.Minute {
		return m.token, nil
	}
	form := url.Values{
		"client_id":     {m.cfg.ClientID},
		"client_secret": {m.cfg.ClientSecret},
		"refresh_token": {m.cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gmail token: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return "", fmt.Errorf("gmail token: %s: unreadable reply", resp.Status)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		// "invalid_grant" means the refresh token was revoked or has expired:
		// run cmd/gmail-auth again and update GMAIL_REFRESH_TOKEN.
		return "", fmt.Errorf("gmail token: %s: %s %s", resp.Status, out.Error, out.ErrorDescription)
	}
	m.token = out.AccessToken
	m.expires = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return m.token, nil
}
