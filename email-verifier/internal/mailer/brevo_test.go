package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrevoMailerSends(t *testing.T) {
	var got struct {
		Sender      brevoAddress   `json:"sender"`
		To          []brevoAddress `json:"to"`
		Subject     string         `json:"subject"`
		TextContent string         `json:"textContent"`
	}
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("api-key")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"messageId":"<1@smtp-relay.mailin.fr>"}`))
	}))
	defer srv.Close()

	m := newBrevoMailer("xkeysib-test", "NodeX <me@gmail.com>")
	m.sendURL = srv.URL
	if err := m.SendOTP(context.Background(), "friend@example.com", "123456", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if key != "xkeysib-test" {
		t.Fatalf("api-key header = %q", key)
	}
	if got.Sender != (brevoAddress{Name: "NodeX", Email: "me@gmail.com"}) || len(got.To) != 1 || got.To[0].Email != "friend@example.com" {
		t.Fatalf("unexpected addresses: %+v", got)
	}
	if got.Subject != otpSubject || !strings.Contains(got.TextContent, "123456") || !strings.Contains(got.TextContent, "10 minutes") {
		t.Fatalf("unexpected content: %+v", got)
	}
}

func TestBrevoMailerReportsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":"invalid_parameter","message":"sender is not valid"}`))
	}))
	defer srv.Close()

	m := newBrevoMailer("key", "me@gmail.com")
	m.sendURL = srv.URL
	err := m.SendOTP(context.Background(), "friend@example.com", "123456", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "sender is not valid") {
		t.Fatalf("want Brevo's reason in the error, got %v", err)
	}
	if m.fromName != "" || m.fromEmail != "me@gmail.com" {
		t.Fatalf("plain sender parsed as %q <%q>", m.fromName, m.fromEmail)
	}
}

func TestOTPMessageRejectsHeaderInjection(t *testing.T) {
	if _, err := otpMessage("me@gmail.com", "a@b.com\r\nBcc: x@y.com", "123456", time.Minute); err == nil {
		t.Fatal("recipient with a line break was accepted")
	}
}
