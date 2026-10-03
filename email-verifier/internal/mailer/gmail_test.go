package mailer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nodex/nodex-backend/internal/config"
)

func TestGmailMailerSendsAndReusesToken(t *testing.T) {
	var tokenCalls int
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls++
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "expires_in": 3600})
		case "/send":
			if r.Header.Get("Authorization") != "Bearer access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var body struct{ Raw string }
			json.NewDecoder(r.Body).Decode(&body)
			raw, err := base64.RawURLEncoding.DecodeString(body.Raw)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			sent = append(sent, string(raw))
			w.Write([]byte(`{"id":"1"}`))
		}
	}))
	defer srv.Close()

	m := newGmailMailer(config.GmailConfig{ClientID: "id", ClientSecret: "secret", RefreshToken: "refresh"}, "NodeX <me@gmail.com>")
	m.tokenURL, m.sendURL = srv.URL+"/token", srv.URL+"/send"

	for range 2 {
		if err := m.SendOTP(context.Background(), "friend@example.com", "123456", 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("token fetched %d times, want 1 (reused)", tokenCalls)
	}
	if len(sent) != 2 || !strings.Contains(sent[0], "To: friend@example.com\r\n") || !strings.Contains(sent[0], "123456") ||
		!strings.Contains(sent[0], "From: NodeX <me@gmail.com>\r\n") {
		t.Fatalf("unexpected message: %q", sent)
	}
}

func TestGmailMailerReportsRevokedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
	}))
	defer srv.Close()

	m := newGmailMailer(config.GmailConfig{ClientID: "id", ClientSecret: "secret", RefreshToken: "old"}, "me@gmail.com")
	m.tokenURL, m.sendURL = srv.URL, srv.URL
	err := m.SendOTP(context.Background(), "friend@example.com", "123456", 10*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("want invalid_grant error, got %v", err)
	}
}

func TestOTPMessageRejectsHeaderInjection(t *testing.T) {
	if _, err := otpMessage("me@gmail.com", "a@b.com\r\nBcc: x@y.com", "123456", time.Minute); err == nil {
		t.Fatal("recipient with a line break was accepted")
	}
}
