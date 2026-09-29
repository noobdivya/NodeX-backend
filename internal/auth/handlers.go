package auth

import (
	"encoding/base64"
	"errors"
	"log"
	"math"
	"net/http"
	"strconv"

	"github.com/nodex/nodex-backend/internal/httpx"
)

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers { return &Handlers{svc: svc} }

// Routes registers the registration endpoints. limit wraps endpoints that
// can send email or be brute-forced.
func (h *Handlers) Routes(mux *http.ServeMux, limit func(http.Handler) http.Handler) {
	mux.Handle("POST /api/v1/auth/register/otp", limit(http.HandlerFunc(h.requestOTP)))
	mux.Handle("POST /api/v1/auth/register/verify", limit(http.HandlerFunc(h.verifyOTP)))
	mux.Handle("POST /api/v1/auth/register/complete", limit(http.HandlerFunc(h.complete)))
	mux.HandleFunc("GET /api/v1/users/username-available", h.usernameAvailable)
}

func (h *Handlers) requestOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.RequestOTP(r.Context(), req.Email); err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"message":            "Verification code sent.",
		"expires_in_seconds": int(otpTTL.Seconds()),
		"resend_in_seconds":  int(otpResendAfter.Seconds()),
	})
}

func (h *Handlers) verifyOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	token, expiresAt, err := h.svc.VerifyOTP(r.Context(), req.Email, req.OTP)
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"registration_token": token,
		"expires_at":         expiresAt.UTC(),
	})
}

func (h *Handlers) complete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegistrationToken string `json:"registration_token"`
		Username          string `json:"username"`
		Password          string `json:"password"`
		ConfirmPassword   string `json:"confirm_password"`
		PeerID            string `json:"peer_id"`
		PublicKey         string `json:"public_key"`
		Signature         string `json:"signature"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	pub, err1 := base64.StdEncoding.DecodeString(req.PublicKey)
	sig, err2 := base64.StdEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || len(pub) == 0 || len(sig) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "identity_invalid", "Public key and signature must be base64-encoded.")
		return
	}

	user, err := h.svc.Register(r.Context(), RegisterInput{
		RegistrationToken: req.RegistrationToken,
		Username:          req.Username,
		Password:          req.Password,
		ConfirmPassword:   req.ConfirmPassword,
		PeerID:            req.PeerID,
		PublicKey:         pub,
		Signature:         sig,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (h *Handlers) usernameAvailable(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	available, err := h.svc.UsernameAvailable(r.Context(), username)
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"username": username, "available": available})
}

func writeErr(w http.ResponseWriter, err error) {
	var e *Error
	if errors.As(err, &e) {
		if e.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(e.RetryAfter.Seconds()))))
		}
		httpx.WriteError(w, e.Status, e.Code, e.Message)
		return
	}
	log.Printf("internal error: %v", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "Something went wrong. Please try again.")
}
