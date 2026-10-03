// Command server runs NodeX's email verifier. It is the only server-side
// piece of NodeX and holds no user data: identities, contacts, chat and
// profiles live on users' devices and travel peer to peer.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nodex/nodex-backend/internal/config"
	"github.com/nodex/nodex-backend/internal/httpx"
	"github.com/nodex/nodex-backend/internal/mailer"
	"github.com/nodex/nodex-backend/internal/otp"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !cfg.SMTP.Enabled() {
		log.Println("SMTP_HOST not set: OTP codes will be printed to this log (development only)")
	}

	svc := otp.NewService(cfg.OTPSecret, mailer.New(cfg.SMTP, cfg.Gmail))
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				svc.Purge()
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	limiter := httpx.NewIPRateLimiter(cfg.RateLimitPerMinute, max(cfg.RateLimitPerMinute/2, 1), cfg.TrustProxy)
	otp.NewHandlers(svc).Routes(mux, limiter.Middleware)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpx.SecurityHeaders(httpx.CORS(cfg.CORSOrigins, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("NodeX email verifier listening on :%s (%s)", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}
