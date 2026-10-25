//go:build integration

/**
 * @spec-handoff
 * @interface aapFixture: HTTP gateway token endpoint
 * @behavior
 *   - Records bearer-authenticated JSON token requests and creates deterministic fixture tokens.
 *   - Deletes exactly the requested issued token; missing tokens return 404 idempotently.
 *   - Can return a deliberately unusable successful issue response for real-Vault cleanup tests.
 * @edge-cases
 *   - Token IDs are positive raw JSON integers and expiry values use RFC3339Nano.
 * @see ./vault_lifecycle_test.go
 */
package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

type fixtureToken struct {
	id      int
	deleted bool
}

type fixtureRequest struct {
	method string
	path   string
	scope  string
}

type aapFixture struct {
	mu             sync.Mutex
	server         *httptest.Server
	tokens         map[int]*fixtureToken
	requests       []fixtureRequest
	nextID         int
	issueExpiry    time.Duration
	issueBody      func(id int) string
	deleteFailures int
}

func newAAPFixture(t interface{ Cleanup(func()) }) *aapFixture {
	f := &aapFixture{
		tokens:      make(map[int]*fixtureToken),
		nextID:      41,
		issueExpiry: 2 * time.Hour,
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *aapFixture) url() string { return f.server.URL }

func (f *aapFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer fixture-issuer" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if _, _, ok := r.BasicAuth(); ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	const endpoint = "/api/gateway/v1/tokens/"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == endpoint:
		var body struct {
			Scope string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Scope != "read" && body.Scope != "write") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.nextID++
		id := f.nextID
		f.tokens[id] = &fixtureToken{id: id}
		f.requests = append(f.requests, fixtureRequest{method: r.Method, path: r.URL.Path, scope: body.Scope})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if f.issueBody != nil {
			_, _ = w.Write([]byte(f.issueBody(id)))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      id,
			"token":   "fixture-child-" + strconv.Itoa(id),
			"expires": time.Now().UTC().Add(f.issueExpiry).Format(time.RFC3339Nano),
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, endpoint):
		id, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, endpoint), "/"))
		if err != nil || id <= 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.requests = append(f.requests, fixtureRequest{method: r.Method, path: r.URL.Path})
		if f.deleteFailures > 0 {
			f.deleteFailures--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		token := f.tokens[id]
		if token == nil || token.deleted {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		token.deleted = true
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *aapFixture) tokenDeleted(id int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[id] != nil && f.tokens[id].deleted
}

func (f *aapFixture) deleteCount(id int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := "/api/gateway/v1/tokens/" + strconv.Itoa(id) + "/"
	count := 0
	for _, request := range f.requests {
		if request.method == http.MethodDelete && request.path == want {
			count++
		}
	}
	return count
}
