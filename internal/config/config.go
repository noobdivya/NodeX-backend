package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env         string
	Port        string
	CORSOrigins []string
	OTPSecret   []byte
	SMTP        SMTPConfig
	// Per-IP limit for the OTP endpoints.
	RateLimitPerMinute int
	// TrustProxy: running behind a hosting proxy (TRUST_PROXY=true).
	TrustProxy bool
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func (s SMTPConfig) Enabled() bool { return s.Host != "" }

func (c Config) IsProduction() bool { return c.Env == "production" }

func Load() (Config, error) {
	if err := loadDotEnv(".env"); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Env:  getenv("APP_ENV", "development"),
		Port: getenv("PORT", "8080"),
		SMTP: SMTPConfig{
			Host:     os.Getenv("SMTP_HOST"),
			Username: os.Getenv("SMTP_USERNAME"),
			Password: os.Getenv("SMTP_PASSWORD"),
			From:     getenv("SMTP_FROM", "NodeX <no-reply@nodex.local>"),
		},
	}

	for _, o := range strings.Split(getenv("CORS_ORIGINS", "http://localhost:3000"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cfg.CORSOrigins = append(cfg.CORSOrigins, o)
		}
	}

	port, err := strconv.Atoi(getenv("SMTP_PORT", "587"))
	if err != nil {
		return cfg, errors.New("SMTP_PORT must be a number")
	}
	cfg.SMTP.Port = port

	cfg.RateLimitPerMinute, err = strconv.Atoi(getenv("RATE_LIMIT_PER_MINUTE", "20"))
	if err != nil || cfg.RateLimitPerMinute < 1 {
		return cfg, errors.New("RATE_LIMIT_PER_MINUTE must be a positive number")
	}
	cfg.TrustProxy = os.Getenv("TRUST_PROXY") == "true"

	if secret := os.Getenv("OTP_SECRET"); secret != "" {
		if len(secret) < 32 {
			return cfg, errors.New("OTP_SECRET must be at least 32 characters")
		}
		cfg.OTPSecret = []byte(secret)
	} else {
		if cfg.IsProduction() {
			return cfg, errors.New("OTP_SECRET is required in production")
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return cfg, err
		}
		cfg.OTPSecret = []byte(hex.EncodeToString(b))
		log.Println("warning: OTP_SECRET not set, using a random per-process secret (development only)")
	}

	if cfg.IsProduction() && !cfg.SMTP.Enabled() {
		return cfg, errors.New("SMTP_HOST is required in production")
	}

	return cfg, nil
}

// loadDotEnv sets KEY=VALUE pairs from path. Variables already set in the
// real environment win, and a missing file is not an error.
func loadDotEnv(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, value)
		}
	}
	log.Printf("loaded settings from %s", path)
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
