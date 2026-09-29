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

	"github.com/nodex/nodex-backend/internal/auth"
	"github.com/nodex/nodex-backend/internal/config"
	"github.com/nodex/nodex-backend/internal/db"
	"github.com/nodex/nodex-backend/internal/httpx"
	"github.com/nodex/nodex-backend/internal/mailer"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	if !cfg.SMTP.Enabled() {
		log.Println("SMTP_HOST not set: OTP codes will be printed to this log (development only)")
	}

	svc := auth.NewService(pool, mailer.New(cfg.SMTP), cfg.OTPSecret)
	go purgeLoop(ctx, svc)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	limiter := httpx.NewIPRateLimiter(cfg.RateLimitPerMinute, max(cfg.RateLimitPerMinute/2, 1))
	auth.NewHandlers(svc).Routes(mux, limiter.Middleware)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpx.SecurityHeaders(httpx.CORS(cfg.CORSOrigins, mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("NodeX backend listening on :%s (%s)", cfg.Port, cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}

func purgeLoop(ctx context.Context, svc *auth.Service) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := svc.PurgeExpired(ctx); err != nil {
				log.Printf("purge expired: %v", err)
			}
		}
	}
}
