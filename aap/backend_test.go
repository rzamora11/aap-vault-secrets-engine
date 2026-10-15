package aap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCredentialsIssueAndRevoke(t *testing.T) {
	ctx := context.Background()
	var issued, revoked bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer issuer-token" {
			t.Fatalf("unexpected issuer authorization header: %q", got)
		}
		if _, _, basicAuth := r.BasicAuth(); basicAuth {
			t.Fatal("request must not use basic authentication")
		}

		switch {
		case r.Method == http.MethodPost && r.URL.Path == gatewayTokensPath:
			issued = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["scope"] != "write" {
				t.Fatalf("unexpected scope: %q", body["scope"])
			}
			if !strings.HasPrefix(body["description"], "vault-aap:terraform-operator:") {
				t.Fatalf("unexpected token description: %q", body["description"])
			}
			writeTokenResponse(t, w, 42, "generated-token", time.Now().Add(2*time.Hour))
		case r.Method == http.MethodDelete && r.URL.Path == gatewayTokensPath+"42/":
			revoked = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "terraform-operator", time.Hour, 2*time.Hour)

	response, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/terraform-operator",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !issued {
		t.Fatal("AAP token was not issued")
	}
	if response.Data["token"] != "generated-token" {
		t.Fatalf("unexpected token: %#v", response.Data["token"])
	}
	if response.Data["host"] != server.URL {
		t.Fatalf("unexpected host: %#v", response.Data["host"])
	}
	if response.Secret == nil || response.Secret.Renewable {
		t.Fatal("issued secret must be non-renewable")
	}
	if response.Secret.TTL < time.Hour-time.Second || response.Secret.TTL > time.Hour {
		t.Fatalf("unexpected lease duration: %s", response.Secret.TTL)
	}

	_, err = backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    response.Secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("AAP token was not revoked")
	}
}

func TestCredentialsCapsLeaseAtAAPExpiry(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != gatewayTokensPath {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		writeTokenResponse(t, w, 7, "short-lived-token", time.Now().Add(30*time.Minute))
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "terraform-operator", time.Hour, 2*time.Hour)

	response, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/terraform-operator",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Secret.TTL > 29*time.Minute || response.Secret.TTL < 28*time.Minute {
		t.Fatalf("AAP expiry did not cap the lease: %s", response.Secret.TTL)
	}
}

func TestConfigReadRedactsSensitiveValues(t *testing.T) {
	ctx := context.Background()
	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, "https://aap.example.test")

	response, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := response.Data["issuer_token"]; found {
		t.Fatal("configuration response exposed issuer token")
	}
	if response.Data["issuer_token_configured"] != true {
		t.Fatalf("issuer token should be reported as configured: %#v", response.Data["issuer_token_configured"])
	}
}

func TestRoleDefaultsToOneHour(t *testing.T) {
	ctx := context.Background()
	backend, storage := testBackend(t)
	_, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/defaults",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	response, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/defaults",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Data["ttl"] != int(defaultTTL.Seconds()) {
		t.Fatalf("unexpected default ttl: %#v", response.Data["ttl"])
	}
	if response.Data["scope"] != "write" {
		t.Fatalf("unexpected default scope: %#v", response.Data["scope"])
	}
}

func TestRevokeTreatsMissingAAPTokenAsSuccess(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != gatewayTokensPath+"gone/" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	secret := backend.aapToken().Response(nil, map[string]interface{}{"token_id": "gone"}).Secret
	_, err := backend.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    secret,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func testBackend(t *testing.T) (*Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	backend, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return backend.(*Backend), config.StorageView
}

func writeConfig(t *testing.T, backend *Backend, storage logical.Storage, serverURL string) {
	t.Helper()
	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":                 serverURL,
			"issuer_token":        "issuer-token",
			"tls_skip_verify":     false,
			"allow_insecure_http": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeRole(t *testing.T, backend *Backend, storage logical.Storage, name string, ttl, maxTTL time.Duration) {
	t.Helper()
	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data: map[string]interface{}{
			"scope":              "write",
			"ttl":                int(ttl.Seconds()),
			"max_ttl":            int(maxTTL.Seconds()),
			"description_prefix": "vault-aap",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeTokenResponse(t *testing.T, response http.ResponseWriter, id int, token string, expiresAt time.Time) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(map[string]interface{}{
		"id":      id,
		"token":   token,
		"expires": expiresAt.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
}
