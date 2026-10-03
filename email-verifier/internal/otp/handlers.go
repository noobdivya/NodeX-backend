package otp

import (
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

// Routes registers the email-verifier endpoints. limit wraps endpoints that
// send email or can be brute-forced.
func (h *Handlers) Routes(mux *http.ServeMux, limit func(http.Handler) http.Handler) {
	mux.Handle("POST /api/v1/otp/send", limit(http.HandlerFunc(h.send)))
	mux.Handle("POST /api/v1/otp/verify", limit(http.HandlerFunc(h.verify)))
}

func (h *Handlers) send(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	token, err := h.svc.Send(r.Context(), req.Email)
	if err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"otp_token":          token,
		"expires_in_seconds": int(codeTTL.Seconds()),
		"resend_in_seconds":  int(resendAfter.Seconds()),
	})
}

func (h *Handlers) verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OTPToken string `json:"otp_token"`
		OTP      string `json:"otp"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := h.svc.Verify(req.OTPToken, req.OTP); err != nil {
		writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
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
