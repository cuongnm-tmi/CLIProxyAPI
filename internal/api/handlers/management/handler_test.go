package management

import (
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

func TestAuthenticateManagementKey_RemoteClientDeniedWhenAllowRemoteDisabled(t *testing.T) {
	h := NewHandler(&config.Config{RemoteManagement: config.RemoteManagement{AllowRemote: false}}, "", nil)

	allowed, statusCode, errMsg := h.AuthenticateManagementKey("203.0.113.10", false, "test-secret")
	if allowed {
		t.Fatal("expected remote auth to be denied when allow-remote is disabled")
	}
	if statusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", statusCode)
	}
	if errMsg != "remote management disabled" {
		t.Fatalf("unexpected error message: %q", errMsg)
	}
}

func TestAuthenticateManagementKey_RemoteClientAllowedByManagementPasswordOverride(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-secret")
	h := NewHandler(&config.Config{RemoteManagement: config.RemoteManagement{AllowRemote: false}}, "", nil)

	allowed, statusCode, errMsg := h.AuthenticateManagementKey("203.0.113.10", false, "test-secret")
	if !allowed {
		t.Fatalf("expected remote auth to be allowed by MANAGEMENT_PASSWORD override, got status=%d msg=%q", statusCode, errMsg)
	}
	if statusCode != 0 || errMsg != "" {
		t.Fatalf("expected successful auth response, got status=%d msg=%q", statusCode, errMsg)
	}
}

func TestAuthenticateManagementKey_LocalhostIPBan_BlocksCorrectKeyDuringBan(t *testing.T) {
	h := &Handler{
		cfg:            &config.Config{},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}

	for i := 0; i < 5; i++ {
		allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "wrong-secret")
		if allowed {
			t.Fatalf("expected auth to be denied at attempt %d", i+1)
		}
		if statusCode != http.StatusUnauthorized || errMsg != "invalid management key" {
			t.Fatalf("unexpected auth failure at attempt %d: status=%d msg=%q", i+1, statusCode, errMsg)
		}
	}

	allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "test-secret")
	if allowed {
		t.Fatalf("expected correct key to be denied while banned")
	}
	if statusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden status while banned, got %d", statusCode)
	}
	if !strings.HasPrefix(errMsg, "IP banned due to too many failed attempts. Try again in") {
		t.Fatalf("unexpected banned message: %q", errMsg)
	}
}
