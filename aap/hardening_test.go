/**
 * @spec-handoff
 * @interface newAAPClient(*config): (*aapClient, error)
 * @interface (*aapClient).issueToken(context.Context, string, string): (*issuedToken, error)
 * @interface (*aapClient).revokeToken(context.Context, string): error
 * @behavior
 *   - Uses only a root HTTPS gateway origin unless HTTP is explicitly enabled.
 *   - Accepts one bounded valid gateway token response and redacts unsafe upstream errors.
 *   - Validates token IDs before issuing a delete and cleans up recoverable unusable issues once.
 * @edge-cases
 *   - IDs are positive raw JSON decimal numbers; invalid IDs never reach the gateway.
 *   - Redirects, malformed bodies, unusable expiry data, and canceled contexts fail safely.
 * @see ./client.go
 */
package aap

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestNewAAPClientRejectsUnsafeGatewayOrigins(t *testing.T) {
	testCases := []struct {
		name string
		url  string
	}{
		{name: "userinfo", url: "https://issuer:password@gateway.example.test"},
		{name: "query", url: "https://gateway.example.test/?next=https://other.example.test"},
		{name: "fragment", url: "https://gateway.example.test/#token"},
		{name: "base path", url: "https://gateway.example.test/api"},
		{name: "encoded base path", url: "https://gateway.example.test/%2Fapi"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := newAAPClient(&config{URL: testCase.url, IssuerToken: "issuer-token"})
			if err == nil {
				t.Fatalf("unsafe gateway origin %q was accepted", testCase.url)
			}
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "issuer-token") {
				t.Fatalf("gateway validation error leaked sensitive input: %v", err)
			}
		})
	}
}

func TestNewAAPClientAllowsOnlyExplicitHTTPOptIn(t *testing.T) {
	_, err := newAAPClient(&config{URL: "http://gateway.example.test", IssuerToken: "issuer-token"})
	if err == nil {
		t.Fatal("HTTP gateway was accepted without allow_insecure_http")
	}

	client, err := newAAPClient(&config{
		URL:               "http://gateway.example.test/",
		IssuerToken:       "issuer-token",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("explicit HTTP opt-in was rejected: %v", err)
	}
	if client.baseURL != "http://gateway.example.test" {
		t.Fatalf("unexpected normalized HTTP origin: %q", client.baseURL)
	}
}

func TestGatewayTLSVerificationRequiresExplicitOptInOrConfiguredCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTokenResponse(t, w, 42, "token", time.Now().Add(time.Hour))
	}))
	defer server.Close()

	defaultClient, err := newAAPClient(&config{URL: server.URL, IssuerToken: "issuer-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultClient.issueToken(context.Background(), "write", "vault-aap:test"); err == nil {
		t.Fatal("default TLS verification accepted an untrusted certificate")
	}

	skipVerifyClient, err := newAAPClient(&config{
		URL:           server.URL,
		IssuerToken:   "issuer-token",
		TLSSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := skipVerifyClient.issueToken(context.Background(), "write", "vault-aap:test"); err != nil {
		t.Fatalf("explicit TLS verification opt-out failed: %v", err)
	}

	caClient, err := newAAPClient(&config{
		URL:         server.URL,
		IssuerToken: "issuer-token",
		CACert: string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: server.Certificate().Raw,
		})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caClient.issueToken(context.Background(), "write", "vault-aap:test"); err != nil {
		t.Fatalf("configured gateway CA did not verify TLS: %v", err)
	}
}

func TestIssueTokenRejectsInvalidGatewayResponseShapes(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	testCases := []struct {
		name string
		body string
	}{
		{name: "zero ID", body: `{"id":0,"token":"gateway-token-secret","expires":"` + expires + `"}`},
		{name: "negative ID", body: `{"id":-1,"token":"gateway-token-secret","expires":"` + expires + `"}`},
		{name: "exponent ID", body: `{"id":1e2,"token":"gateway-token-secret","expires":"` + expires + `"}`},
		{name: "fractional ID", body: `{"id":1.5,"token":"gateway-token-secret","expires":"` + expires + `"}`},
		{name: "string ID", body: `{"id":"42","token":"gateway-token-secret","expires":"` + expires + `"}`},
		{name: "missing token", body: `{"id":42,"token":"","expires":"` + expires + `"}`},
		{name: "missing expires", body: `{"id":42,"token":"gateway-token-secret"}`},
		{name: "expires in fallback", body: `{"id":42,"token":"gateway-token-secret","expires_in":3600}`},
		{name: "invalid expires", body: `{"id":42,"token":"gateway-token-secret","expires":"tomorrow"}`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(testCase.body))
			})
			defer server.Close()

			_, err := client.issueToken(context.Background(), "write", "vault-aap:test")
			if err == nil {
				t.Fatal("invalid gateway token response was accepted")
			}
			if strings.Contains(err.Error(), "gateway-token-secret") {
				t.Fatalf("gateway response error leaked token: %v", err)
			}
		})
	}
}

func TestIssueTokenRejectsOversizedAndAmbiguousJSON(t *testing.T) {
	testCases := []struct {
		name string
		body func() string
	}{
		{
			name: "oversized body",
			body: func() string {
				return `{"id":42,"token":"` + strings.Repeat("x", 1<<20) + `","expires":"2030-01-01T00:00:00Z"}`
			},
		},
		{
			name: "trailing JSON value",
			body: func() string {
				return `{"id":42,"token":"token","expires":"2030-01-01T00:00:00Z"} {}`
			},
		},
		{
			name: "malformed JSON",
			body: func() string {
				return `{"id":42,"token":"token","expires":`
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(testCase.body()))
			})
			defer server.Close()

			if _, err := client.issueToken(context.Background(), "write", "vault-aap:test"); err == nil {
				t.Fatal("invalid successful response was accepted")
			}
		})
	}
}

func TestIssueTokenAllowsOneJSONValueAndTrailingWhitespace(t *testing.T) {
	client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{\"id\":42,\"token\":\"token\",\"expires\":\"2030-01-01T00:00:00.123456789Z\"}\n\t "))
	})
	defer server.Close()

	token, err := client.issueToken(context.Background(), "write", "vault-aap:test")
	if err != nil {
		t.Fatalf("valid gateway response was rejected: %v", err)
	}
	if token.ID != "42" || token.Token != "token" {
		t.Fatalf("unexpected issued token: %#v", token)
	}
}

func TestIssueTokenRedactsUpstreamErrorBodies(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("upstream-body-with-gateway-token-secret"))
			})
			defer server.Close()

			_, err := client.issueToken(context.Background(), "write", "vault-aap:test")
			if err == nil {
				t.Fatalf("status %d was accepted", status)
			}
			if strings.Contains(err.Error(), "gateway-token-secret") {
				t.Fatalf("status %d leaked upstream body: %v", status, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("status %d was not preserved in safe error: %v", status, err)
			}
		})
	}
}

func TestIssueTokenDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()

	client, server := testGatewayClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	defer server.Close()

	if _, err := client.issueToken(context.Background(), "write", "vault-aap:test"); err == nil {
		t.Fatal("redirected issue request succeeded")
	}
	if redirected.Load() {
		t.Fatal("redirect target received a credential-bearing request")
	}
}

func TestRevokeTokenRejectsUnsafeIDsBeforeSendingRequest(t *testing.T) {
	unsafeIDs := []string{"0", "-1", "1e2", "1.5", "42/../other", "%2fother", "٤٢", "token"}
	for _, tokenID := range unsafeIDs {
		t.Run(tokenID, func(t *testing.T) {
			var requests atomic.Int32
			client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			defer server.Close()

			if err := client.revokeToken(context.Background(), tokenID); err == nil {
				t.Fatalf("unsafe token ID %q was accepted", tokenID)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("unsafe token ID %q sent %d gateway requests", tokenID, got)
			}
		})
	}
}

func TestRevokeTokenTreats2xxAnd404AsSuccess(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, server := testGatewayClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != gatewayTokensPath+"42/" {
					t.Fatalf("unexpected revoke request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(status)
			})
			defer server.Close()

			if err := client.revokeToken(context.Background(), "42"); err != nil {
				t.Fatalf("status %d did not revoke idempotently: %v", status, err)
			}
		})
	}
}

func TestCredentialIssueCleansUpRecoverableUnusableGatewayResponse(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == gatewayTokensPath:
			_, _ = w.Write([]byte(`{"id":42,"token":"","expires":"2030-01-01T00:00:00Z"}`))
		case r.Method == http.MethodDelete && r.URL.Path == gatewayTokensPath+"42/":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "cleanup", time.Hour, time.Hour)
	response, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/cleanup",
		Storage:   storage,
	})
	if err == nil || response != nil {
		t.Fatalf("unusable gateway response issued a lease: response=%#v err=%v", response, err)
	}
	if strings.Contains(err.Error(), "issuer-token") || strings.Contains(err.Error(), "token\":\"") {
		t.Fatalf("credential issue error leaked sensitive response data: %v", err)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("recoverable unusable issue triggered %d cleanup deletes, want 1", got)
	}
}

func TestCredentialIssuePreservesPrimaryErrorWhenCleanupFails(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == gatewayTokensPath:
			_, _ = w.Write([]byte(`{"id":42,"token":"","expires":"2030-01-01T00:00:00Z"}`))
		case r.Method == http.MethodDelete && r.URL.Path == gatewayTokensPath+"42/":
			deletes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("cleanup-failure-gateway-token-secret"))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "cleanup-failure", time.Hour, time.Hour)
	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/cleanup-failure",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("unusable gateway response issued a lease")
	}
	if !strings.Contains(err.Error(), "token response") {
		t.Fatalf("cleanup failure replaced the primary response error: %v", err)
	}
	if strings.Contains(err.Error(), "cleanup-failure-gateway-token-secret") {
		t.Fatalf("cleanup failure leaked its upstream body: %v", err)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("recoverable unusable issue triggered %d cleanup deletes, want 1", got)
	}
}

func TestCredentialLeaseTTLUsesSmallestConfiguredAndUpstreamLimit(t *testing.T) {
	expires := time.Now().Add(90 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTokenResponse(t, w, 42, "token", expires)
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "limited", 2*time.Hour, 3*time.Hour)
	response, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/limited",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Secret.TTL > 89*time.Minute || response.Secret.TTL < 88*time.Minute {
		t.Fatalf("lease TTL %s did not use upstream expiry minus safety margin", response.Secret.TTL)
	}
	if response.Secret.Renewable {
		t.Fatal("gateway lease is renewable")
	}
}

func TestRoleDeletionDoesNotPreventIssuedLeaseRevocation(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == gatewayTokensPath:
			writeTokenResponse(t, w, 42, "token", time.Now().Add(time.Hour))
		case r.Method == http.MethodDelete && r.URL.Path == gatewayTokensPath+"42/":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, server.URL)
	writeRole(t, backend, storage, "operator", time.Hour, time.Hour)
	issued, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/operator",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/operator",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Storage:   storage,
		Secret:    issued.Secret,
	})
	if err != nil {
		t.Fatalf("issued lease could not be revoked after role deletion: %v", err)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("issued lease sent %d revoke deletes, want 1", got)
	}
}

func testGatewayClient(t *testing.T, handler http.HandlerFunc) (*aapClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := newAAPClient(&config{
		URL:               server.URL,
		IssuerToken:       "issuer-token",
		AllowInsecureHTTP: true,
	})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server
}

func TestConfigurationAndRoleValidationPreserveSafeDefaults(t *testing.T) {
	backend, storage := testBackend(t)
	_, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":          "https://gateway.example.test",
			"issuer_token": "issuer-token",
		},
	})
	if err != nil {
		t.Fatalf("valid HTTPS configuration was rejected: %v", err)
	}

	for _, data := range []map[string]interface{}{
		{"scope": "admin", "ttl": 60, "max_ttl": 60},
		{"scope": "read", "ttl": 120, "max_ttl": 60},
		{"scope": "write", "ttl": 0, "max_ttl": 60},
	} {
		requestData := map[string]interface{}{"description_prefix": "vault-aap"}
		for key, value := range data {
			requestData[key] = value
		}
		_, err := backend.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/invalid",
			Storage:   storage,
			Data:      requestData,
		})
		if err == nil {
			t.Fatalf("invalid role data %#v was accepted", data)
		}
	}
}

func TestConfigAndRoleReplacementPreserveCRUDAndListSemantics(t *testing.T) {
	backend, storage := testBackend(t)
	writeConfig(t, backend, storage, "https://first.example.test")
	writeConfig(t, backend, storage, "https://replacement.example.test")
	writeRole(t, backend, storage, "operator", time.Hour, 2*time.Hour)
	writeRole(t, backend, storage, "operator", 30*time.Minute, time.Hour)

	configResponse, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if configResponse.Data["url"] != "https://replacement.example.test" {
		t.Fatalf("config replacement was not retained: %#v", configResponse.Data)
	}
	if _, found := configResponse.Data["issuer_token"]; found {
		t.Fatal("config replacement exposed issuer token")
	}

	roleResponse, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/operator",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if roleResponse.Data["ttl"] != int((30 * time.Minute).Seconds()) {
		t.Fatalf("role replacement was not retained: %#v", roleResponse.Data)
	}

	listResponse, err := backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := listResponse.Data["keys"].([]string)
	if !ok || len(keys) != 1 || keys[0] != "operator" {
		t.Fatalf("role list did not retain the replacement role: %#v", listResponse.Data)
	}
}

func TestCredentialIssueUsesBearerAuthenticationWithoutRetries(t *testing.T) {
	var posts atomic.Int32
	client, server := testGatewayClient(t, func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer issuer-token" {
			t.Fatalf("unexpected authorization: %q", got)
		}
		if _, _, ok := r.BasicAuth(); ok {
			t.Fatal("gateway request used basic authentication")
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	if _, err := client.issueToken(context.Background(), "write", "vault-aap:test"); err == nil {
		t.Fatal("failed POST succeeded")
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("failed POST made %d attempts, want 1", got)
	}
}

func TestIssueTokenHonorsCanceledContext(t *testing.T) {
	client, server := testGatewayClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("canceled request reached the gateway")
	})
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := client.issueToken(ctx, "write", "vault-aap:test"); err == nil {
		t.Fatal("canceled request succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled request waited %s", elapsed)
	}
}
