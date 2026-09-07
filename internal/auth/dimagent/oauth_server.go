package dimagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// OAuthServer is the local HTTP server that receives the DimAgent OAuth
// browser redirect. It listens on the fixed callback port derived from the
// registered redirect URI (http://localhost:54321/auth/callback).
type OAuthServer struct {
	port       int
	server     *http.Server
	running    bool
	mu         sync.Mutex
	resultChan chan *OAuthResult
	errorChan  chan error
}

// OAuthResult carries the callback parameters captured from the browser redirect.
type OAuthResult struct {
	Code  string
	State string
	Error string
}

// NewOAuthServer creates a callback server bound to the given port.
func NewOAuthServer(port int) *OAuthServer {
	if port <= 0 {
		port = CallbackPort
	}
	return &OAuthServer{
		port:       port,
		resultChan: make(chan *OAuthResult, 1),
		errorChan:  make(chan error, 1),
	}
}

// Start starts the OAuth callback server.
func (s *OAuthServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server is already running")
	}

	if !s.isPortAvailable() {
		return fmt.Errorf("port %d is already in use; close the DimAgent desktop app if it is running", s.port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", s.handleCallback)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s.running = true

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case s.errorChan <- fmt.Errorf("server failed to start: %w", err):
			default:
			}
		}
	}()

	// Give the server a moment to bind the port.
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Stop gracefully stops the OAuth callback server.
func (s *OAuthServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(shutdownCtx)
	s.running = false
	s.server = nil

	return err
}

// WaitForCallback blocks until an OAuth result arrives, an error occurs, or
// the timeout elapses.
func (s *OAuthServer) WaitForCallback(timeout time.Duration) (*OAuthResult, error) {
	select {
	case result := <-s.resultChan:
		return result, nil
	case err := <-s.errorChan:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for OAuth callback")
	}
}

// IsRunning reports whether the callback server is currently listening.
func (s *OAuthServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// handleCallback captures the authorization code (or error) from the redirect.
func (s *OAuthServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Debug("dimagent: received OAuth callback")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	result := &OAuthResult{
		Code:  strings.TrimSpace(query.Get("code")),
		State: strings.TrimSpace(query.Get("state")),
		Error: strings.TrimSpace(firstNonEmptyQuery(query.Get("error"), query.Get("error_description"))),
	}

	s.sendResult(result)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if result.Error != "" {
		_, _ = fmt.Fprint(w, failurePage(result.Error))
		return
	}
	_, _ = fmt.Fprint(w, successPage())
}

func (s *OAuthServer) sendResult(result *OAuthResult) {
	select {
	case s.resultChan <- result:
	default:
		log.Debug("dimagent: callback already captured, ignoring duplicate")
	}
}

func (s *OAuthServer) isPortAvailable() bool {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func firstNonEmptyQuery(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

const callbackSuccessHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>DimAgent Authentication</title></head>
<body style="font-family: system-ui, sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; background:#f7f7f8;">
  <div style="text-align:center; padding:32px;">
    <h2 style="color:#16a34a; margin-bottom:8px;">✓ Authentication successful</h2>
    <p style="color:#52525b;">DimAgent account has been added. You can close this window and return to your terminal.</p>
  </div>
</body>
</html>`

const callbackFailureHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>DimAgent Authentication</title></head>
<body style="font-family: system-ui, sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; background:#f7f7f8;">
  <div style="text-align:center; padding:32px;">
    <h2 style="color:#dc2626; margin-bottom:8px;">Authentication failed</h2>
    <p style="color:#52525b;">%s</p>
    <p style="color:#52525b;">Return to your terminal for details.</p>
  </div>
</body>
</html>`

func successPage() string { return callbackSuccessHTML }
func failurePage(err string) string {
	return fmt.Sprintf(callbackFailureHTML, strings.TrimSpace(err))
}
