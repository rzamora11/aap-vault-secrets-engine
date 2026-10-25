//go:build integration

/**
 * @spec-handoff
 * @interface Vault logical aap/creds/:role, sys/leases/renew, sys/leases/revoke
 * @behavior
 *   - Uses a real Vault subprocess and the built or supplied external plugin binary.
 *   - Issues nonrenewable leases capped by role, mount, and fixture expiry, and revokes fixture tokens.
 *   - Preserves state across a file-storage Vault restart before revoking an existing lease.
 * @edge-cases
 *   - Missing upstream tokens are idempotent; failed revokes remain failed and can recover.
 *   - A malformed successful upstream response with a known numeric ID must trigger cleanup.
 * @see ../../aap/token.go
 */
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

const pluginName = "vault-plugin-secrets-aap"

type vaultHarness struct {
	t          *testing.T
	dir        string
	storageDir string
	pluginDir  string
	pluginPath string
	address    string
	rootToken  string
	unsealKey  string
	client     *api.Client
	cmd        *exec.Cmd
}

func TestRealVaultLifecycleIssuesCapsAndExplicitlyRevokes(t *testing.T) {
	fixture := newAAPFixture(t)
	fixture.issueExpiry = 70 * time.Minute
	vault := newVaultHarness(t, fixture)
	config, err := vault.client.Logical().Read("aap/config")
	if err != nil || config == nil {
		t.Fatalf("read redacted plugin configuration: %v", err)
	}
	if _, exposed := config.Data["issuer_token"]; exposed || config.Data["issuer_token_configured"] != true {
		t.Fatalf("configuration did not redact the issuer credential: %#v", config.Data)
	}
	secret := vault.issue(t, "writer", "write", "90m", "120m")
	if secret.LeaseID == "" || secret.LeaseDuration <= 0 || secret.LeaseDuration > 60*60 {
		t.Fatalf("unexpected bounded lease metadata: id present=%t duration=%d", secret.LeaseID != "", secret.LeaseDuration)
	}
	if secret.Renewable {
		t.Fatal("credential lease must be nonrenewable")
	}
	if _, err := vault.client.Sys().Renew(secret.LeaseID, 60); err == nil {
		t.Fatal("nonrenewable lease renewal succeeded")
	}
	id := fixtureID(secret)
	if err := vault.client.Sys().Revoke(secret.LeaseID); err != nil {
		t.Fatalf("explicit Vault revoke failed: %v", err)
	}
	if !fixture.tokenDeleted(id) {
		t.Fatal("explicit Vault revoke did not delete the issued fixture token")
	}
	if got := fixture.deleteCount(id); got != 1 {
		t.Fatalf("explicit revoke sent %d fixture deletes, want 1", got)
	}
}

func TestRealVaultExpiryAutomaticallyRevokesAnd404IsIdempotent(t *testing.T) {
	fixture := newAAPFixture(t)
	fixture.issueExpiry = 62 * time.Second
	vault := newVaultHarness(t, fixture)
	secret := vault.issue(t, "short", "read", "2s", "2s")
	id := fixtureID(secret)
	if !eventually(12*time.Second, 100*time.Millisecond, func() bool { return fixture.tokenDeleted(id) }) {
		t.Fatal("expired Vault lease did not automatically delete the fixture token")
	}
	if err := vault.client.Sys().Revoke(secret.LeaseID); err != nil {
		t.Fatalf("repeat revoke after upstream deletion was not idempotent: %v", err)
	}
}

func TestRealVaultRevokeFailureIsVisibleAndRetryRecovers(t *testing.T) {
	fixture := newAAPFixture(t)
	vault := newVaultHarness(t, fixture)
	secret := vault.issue(t, "retry", "write", "5m", "5m")
	id := fixtureID(secret)
	fixture.deleteFailures = 1
	if err := vault.client.Sys().Revoke(secret.LeaseID); err == nil {
		t.Fatal("Vault reported a failed upstream revoke as successful")
	}
	if fixture.tokenDeleted(id) {
		t.Fatal("fixture token was deleted despite configured revoke failure")
	}
	if err := vault.client.Sys().Revoke(secret.LeaseID); err != nil {
		t.Fatalf("revoke retry did not recover: %v", err)
	}
	if !fixture.tokenDeleted(id) || fixture.deleteCount(id) != 2 {
		t.Fatal("recovery did not delete exactly the originally issued fixture token")
	}
}

func TestRealVaultRestartRetainsLeaseAndRevokesOriginalToken(t *testing.T) {
	fixture := newAAPFixture(t)
	vault := newVaultHarness(t, fixture)
	secret := vault.issue(t, "restart", "write", "5m", "5m")
	id := fixtureID(secret)
	vault.restart(t)
	if err := vault.client.Sys().Revoke(secret.LeaseID); err != nil {
		t.Fatalf("pre-restart lease did not revoke after persistent Vault restart: %v", err)
	}
	if !fixture.tokenDeleted(id) {
		t.Fatal("restart revoke did not delete the original fixture token")
	}
}

func TestRealVaultCleansKnownIDAfterMalformedSuccessfulIssue(t *testing.T) {
	fixture := newAAPFixture(t)
	fixture.issueBody = func(id int) string {
		return fmt.Sprintf(`{"id":%d,"token":`, id)
	}
	vault := newVaultHarness(t, fixture)
	if _, err := vault.client.Logical().Read("aap/creds/malformed"); err == nil {
		t.Fatal("malformed successful upstream issue response produced a Vault credential")
	}
	if got := fixture.deleteCount(42); got != 1 {
		t.Fatalf("malformed response with known token ID sent %d cleanup deletes, want 1", got)
	}
}

func newVaultHarness(t *testing.T, fixture *aapFixture) *vaultHarness {
	t.Helper()
	vaultBinary := requiredExecutable(t, "VAULT_BINARY", "vault")
	dir := t.TempDir()
	h := &vaultHarness{t: t, dir: dir, storageDir: filepath.Join(dir, "storage"), pluginDir: filepath.Join(dir, "plugins")}
	if err := os.MkdirAll(h.storageDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.pluginDir, 0700); err != nil {
		t.Fatal(err)
	}
	h.pluginPath = pluginExecutable(t, h.pluginDir)
	h.address = "http://" + loopbackAddress(t)
	t.Cleanup(h.stop)
	h.start(t, vaultBinary, false)
	h.initialize(t)
	h.registerAndMount(t, fixture)
	return h
}

func requiredExecutable(t *testing.T, envName, fallback string) string {
	t.Helper()
	if value, ok := os.LookupEnv(envName); ok {
		info, err := os.Stat(value)
		if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			t.Fatalf("%s must name an executable file", envName)
		}
		return value
	}
	path, err := exec.LookPath(fallback)
	if err != nil {
		if os.Getenv("VAULT_INTEGRATION_ALLOW_SKIP") == "1" {
			t.Skip("Vault executable unavailable under explicit local opt-in")
		}
		t.Fatalf("Vault executable is required; set VAULT_BINARY or install vault: %v", err)
	}
	return path
}

func pluginExecutable(t *testing.T, pluginDir string) string {
	t.Helper()
	name := pluginName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	destination := filepath.Join(pluginDir, name)
	if supplied, ok := os.LookupEnv("VAULT_PLUGIN_BINARY"); ok {
		info, err := os.Stat(supplied)
		if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			t.Fatal("VAULT_PLUGIN_BINARY must name an executable file")
		}
		input, err := os.Open(supplied)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(output, input); err != nil {
			output.Close()
			t.Fatal(err)
		}
		if err = output.Close(); err != nil {
			t.Fatal(err)
		}
		return destination
	}
	repoRoot := repositoryRoot(t)
	command := exec.Command("go", "build", "-o", destination, "./cmd/vault-plugin-secrets-aap")
	command.Dir = repoRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v (%s)", err, sanitize(output))
	}
	return destination
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository go.mod")
		}
		dir = parent
	}
}

func loopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func (h *vaultHarness) start(t *testing.T, binary string, initialized bool) {
	t.Helper()
	config := fmt.Sprintf("storage \"file\" { path = %q }\nlistener \"tcp\" { address = %q tls_disable = 1 }\ndisable_mlock = true\napi_addr = %q\nplugin_directory = %q\n", h.storageDir, strings.TrimPrefix(h.address, "http://"), h.address, h.pluginDir)
	configPath := filepath.Join(h.dir, "vault.hcl")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	h.cmd = exec.Command(binary, "server", "-config="+configPath)
	h.cmd.Stdout = new(bytes.Buffer)
	h.cmd.Stderr = new(bytes.Buffer)
	h.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("start Vault: %v", err)
	}
	configAPI := api.DefaultConfig()
	configAPI.Address = h.address
	configAPI.HttpClient.Timeout = 500 * time.Millisecond
	client, err := api.NewClient(configAPI)
	if err != nil {
		t.Fatal(err)
	}
	h.client = client
	if !eventually(10*time.Second, 100*time.Millisecond, func() bool { _, err := h.client.Sys().Health(); return err == nil }) {
		t.Fatal("Vault readiness polling timed out")
	}
	if initialized {
		h.client.SetToken(h.rootToken)
		if _, err := h.client.Sys().Unseal(h.unsealKey); err != nil {
			t.Fatalf("unseal restarted Vault: %v", err)
		}
	}
}

func (h *vaultHarness) initialize(t *testing.T) {
	t.Helper()
	response, err := h.client.Sys().Init(&api.InitRequest{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("initialize Vault: %v", err)
	}
	h.rootToken, h.unsealKey = response.RootToken, response.Keys[0]
	if _, err := h.client.Sys().Unseal(h.unsealKey); err != nil {
		t.Fatalf("unseal Vault: %v", err)
	}
	h.client.SetToken(h.rootToken)
}

func (h *vaultHarness) registerAndMount(t *testing.T, fixture *aapFixture) {
	t.Helper()
	digest, err := executableSHA256(h.pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.client.Sys().RegisterPlugin(&api.RegisterPluginInput{Name: pluginName, Type: api.PluginTypeSecrets, Command: filepath.Base(h.pluginPath), SHA256: digest}); err != nil {
		t.Fatalf("register plugin: %v", err)
	}
	if err := h.client.Sys().Mount("aap", &api.MountInput{Type: pluginName, Config: api.MountConfigInput{DefaultLeaseTTL: "1h", MaxLeaseTTL: "1h"}}); err != nil {
		t.Fatalf("mount plugin: %v", err)
	}
	if _, err := h.client.Logical().Write("aap/config", map[string]interface{}{"url": fixture.url(), "issuer_token": "fixture-issuer", "allow_insecure_http": true}); err != nil {
		t.Fatalf("configure plugin: %v", err)
	}
}

func (h *vaultHarness) issue(t *testing.T, role, scope, ttl, maxTTL string) *api.Secret {
	t.Helper()
	if _, err := h.client.Logical().Write("aap/roles/"+role, map[string]interface{}{"scope": scope, "ttl": ttl, "max_ttl": maxTTL, "description_prefix": "vault-aap"}); err != nil {
		t.Fatalf("write role: %v", err)
	}
	secret, err := h.client.Logical().Read("aap/creds/" + role)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	if secret == nil {
		t.Fatal("credential issue returned no secret")
	}
	return secret
}

func (h *vaultHarness) restart(t *testing.T) {
	h.stop()
	h.start(t, requiredExecutable(t, "VAULT_BINARY", "vault"), true)
}

func (h *vaultHarness) stop() {
	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-h.cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-h.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	h.cmd = nil
}

func executableSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func fixtureID(secret *api.Secret) int {
	value, _ := secret.Data["token"].(string)
	return int(parseFixtureID(value))
}
func parseFixtureID(token string) int64 {
	var id int64
	_, _ = fmt.Sscanf(token, "fixture-child-%d", &id)
	return id
}
func eventually(limit, interval time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(interval)
	}
	return condition()
}
func sanitize(output []byte) string {
	return strings.TrimSpace(strings.ReplaceAll(string(output), "\n", " "))
}
