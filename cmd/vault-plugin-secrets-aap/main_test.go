/**
 * @spec-handoff
 * @interface main(): void
 * @behavior
 *   - Invalid or malformed Vault plugin flags exit unsuccessfully before TLS configuration or plugin serving starts.
 *   - Successfully parsed flags continue through the same plugin startup entrypoint.
 * @edge-cases
 *   - An unknown flag and an invalid boolean flag both stop at parsing.
 * @see ./main.go
 */
package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainStopsBeforePluginServeWhenFlagParsingFails(t *testing.T) {
	binary := buildPluginBinary(t)

	for _, argument := range []string{"-unknown-plugin-flag", "-tls-skip-verify=not-a-boolean"} {
		t.Run(argument, func(t *testing.T) {
			output, err := exec.Command(binary, argument).CombinedOutput()
			if err == nil {
				t.Fatalf("invalid flag %q exited successfully: %s", argument, output)
			}
			if !strings.Contains(string(output), "flag provided but not defined") && !strings.Contains(string(output), "parse error") {
				t.Fatalf("invalid flag %q did not report a parse failure: %s", argument, output)
			}
			if strings.Contains(string(output), "This binary is a plugin") || strings.Contains(string(output), "plugin shutting down") {
				t.Fatalf("invalid flag %q reached plugin.Serve: %s", argument, output)
			}
		})
	}
}

func TestMainReachesPluginServeAfterSuccessfulFlagParsing(t *testing.T) {
	binary := buildPluginBinary(t)
	output, err := exec.Command(binary, "-tls-skip-verify=true").CombinedOutput()
	if err == nil {
		t.Fatalf("plugin unexpectedly served without a Vault host: %s", output)
	}
	if !strings.Contains(string(output), "This binary is a plugin") && !strings.Contains(string(output), "plugin shutting down") {
		t.Fatalf("successfully parsed flags did not continue to plugin.Serve: %s", output)
	}
}

func buildPluginBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "vault-plugin-secrets-aap")
	command := exec.Command("go", "build", "-o", binary, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v: %s", err, output)
	}
	return binary
}
