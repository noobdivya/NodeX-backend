// Command gmail-auth connects the email verifier to a Gmail account, once.
//
// It opens Google's sign-in page, asks only for permission to send email
// (gmail.send), and prints the refresh token to put in GMAIL_REFRESH_TOKEN.
// Run it on your own computer:
//
//	go run ./cmd/gmail-auth
//
// It needs an OAuth client of type "Desktop app" (GMAIL_CLIENT_ID and
// GMAIL_CLIENT_SECRET, from the environment or typed in when asked).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/nodex/nodex-backend/internal/mailer"
)

func main() {
	in := bufio.NewReader(os.Stdin)
	clientID := valueOrAsk(in, "GMAIL_CLIENT_ID", "OAuth client ID")
	clientSecret := valueOrAsk(in, "GMAIL_CLIENT_SECRET", "OAuth client secret")

	// Google sends the browser back to this computer only.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	state := randomString()
	verifier := randomString()
	challenge := sha256.Sum256([]byte(verifier))

	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {mailer.GmailSendScope},
		"access_type":           {"offline"},
		"prompt":                {"consent"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}.Encode()

	codes := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "This sign-in didn't come from gmail-auth. Run it again.", http.StatusBadRequest)
			return
		}
		if e := q.Get("error"); e != "" {
			fmt.Fprintf(w, "Google said: %s. You can close this tab and run gmail-auth again.", e)
			codes <- ""
			return
		}
		fmt.Fprint(w, "NodeX is connected to Gmail. You can close this tab and go back to the terminal.")
		codes <- q.Get("code")
	})}
	go srv.Serve(ln)

	fmt.Println("\nOpening Google sign-in. If the browser doesn't open, visit:\n\n  " + authURL + "\n")
	fmt.Println("Sign in with the Gmail account NodeX should send from, and allow \"Send email on your behalf\".")
	openBrowser(authURL)

	code := <-codes
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
	cancel()
	if code == "" {
		log.Fatal("no permission was given")
	}

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirect},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		RefreshToken     string `json:"refresh_token"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.RefreshToken == "" {
		log.Fatalf("Google didn't return a refresh token: %s %s", out.Error, out.ErrorDescription)
	}
	if !strings.Contains(out.Scope, mailer.GmailSendScope) {
		log.Fatal("permission to send email wasn't granted; run it again and tick it")
	}

	fmt.Println("\nDone. Put these three values in the verifier's settings (Render → nodex-verifier → Environment):")
	fmt.Println("\n  GMAIL_CLIENT_ID=" + clientID)
	fmt.Println("  GMAIL_CLIENT_SECRET=<the client secret you used>")
	fmt.Println("  GMAIL_REFRESH_TOKEN=" + out.RefreshToken)
	fmt.Println("\nKeep the refresh token private: it lets anyone send email as this account.")
}

func valueOrAsk(in *bufio.Reader, env, label string) string {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	for {
		fmt.Printf("%s: ", label)
		line, err := in.ReadString('\n')
		if v := strings.TrimSpace(line); v != "" {
			return v
		}
		if err != nil {
			log.Fatalf("%s is required", env)
		}
	}
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}
