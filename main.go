package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  string   `yaml:"listen"`
	APIKeys []string `yaml:"api_keys"`
	Relays  []Relay  `yaml:"relays"`
}

type Relay struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
}

type SendRequest struct {
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	Body    string            `json:"body"`
	HTML    bool              `json:"html"`
	Headers map[string]string `json:"headers"`
}

type SendResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Relay string `json:"relay,omitempty"`
}

var (
	cfg      Config
	relayIdx atomic.Int64
)

func nextRelay() Relay {
	idx := int(relayIdx.Add(1)-1) % len(cfg.Relays)
	return cfg.Relays[idx]
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		for _, k := range cfg.APIKeys {
			if k == key {
				next(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(SendResponse{OK: false, Error: "unauthorized"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type unencryptedAuth struct {
	smtp.Auth
}

func (a unencryptedAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return a.Auth.Start(&s)
}

type loginAuth struct {
	username, password string
}

func (a loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch strings.ToLower(string(fromServer)) {
		case "username:":
			return []byte(a.username), nil
		case "password:":
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unexpected server challenge: %s", fromServer)
		}
	}
	return nil, nil
}

func sendMail(relay Relay, req SendRequest) error {
	addr := fmt.Sprintf("%s:%d", relay.Host, relay.Port)

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	c, err := smtp.NewClient(conn, relay.Host)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		c.StartTLS(&tls.Config{ServerName: relay.Host, InsecureSkipVerify: true})
	}

	auth := unencryptedAuth{smtp.PlainAuth("", relay.From, relay.Password, relay.Host)}
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	if err := c.Mail(relay.From); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, to := range req.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt %s: %w", to, err)
		}
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}

	contentType := "text/plain; charset=UTF-8"
	if req.HTML {
		contentType = "text/html; charset=UTF-8"
	}

	msgID := fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), relay.Host)
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: %s\r\nDate: %s\r\nContent-Type: %s\r\nMIME-Version: 1.0\r\n",
		relay.From,
		strings.Join(req.To, ", "),
		req.Subject,
		msgID,
		time.Now().Format(time.RFC1123Z),
		contentType,
	)
	for k, v := range req.Headers {
		headers += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	headers += "\r\n"

	wc.Write([]byte(headers))
	wc.Write([]byte(req.Body))
	wc.Close()
	return c.Quit()
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, SendResponse{OK: false, Error: "method not allowed"})
		return
	}

	var req SendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, SendResponse{OK: false, Error: "invalid json"})
		return
	}
	if len(req.To) == 0 {
		writeJSON(w, http.StatusBadRequest, SendResponse{OK: false, Error: "to is required"})
		return
	}
	if req.Subject == "" {
		writeJSON(w, http.StatusBadRequest, SendResponse{OK: false, Error: "subject is required"})
		return
	}

	relay := nextRelay()
	if err := sendMail(relay, req); err != nil {
		log.Printf("send error via %s: %v", relay.Host, err)
		writeJSON(w, http.StatusBadGateway, SendResponse{OK: false, Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, SendResponse{OK: true, Relay: relay.Host})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "relays": len(cfg.Relays)})
}

func main() {
	path := "config.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if len(cfg.Relays) == 0 {
		log.Fatal("no relays configured")
	}
	if len(cfg.APIKeys) == 0 {
		log.Fatal("no api_keys configured")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/send", authMiddleware(handleSend))
	mux.HandleFunc("/health", handleHealth)

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("mail API listening on %s", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Close()
}
