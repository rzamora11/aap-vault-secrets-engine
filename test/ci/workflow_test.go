/**
 * @spec-handoff
 * @interface validateReleaseJob(map[string]interface{}): error
 * @interface validateVaultInstaller(map[string]interface{}): error
 * @behavior
 *   - A tagged release waits for successful quality and integration jobs.
 *   - Vault checksum verification authenticates the signed manifest with HashiCorp's pinned signing identity before extracting an archive.
 * @edge-cases
 *   - Missing release dependencies, signature verification, or a valid signing subkey fail the workflow contract.
 * @see ../../.github/workflows/ci.yml
 */
package ci

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	workflowPath      = "../../.github/workflows/ci.yml"
	trustedPrimaryKey = "C874011F0AB405110D02105534365D9472D7468F"
	trustedSigningKey = "374EC75B485913604A831CC7C820C6D5CD27AB87"
	hashicorpKeyURL   = "https://www.hashicorp.com/.well-known/pgp-key.txt"
)

func TestReleaseWorkflowRequiresSuccessfulQualityAndIntegration(t *testing.T) {
	workflow := loadWorkflow(t)
	if err := validateReleaseJob(workflow); err != nil {
		t.Fatalf("CI workflow violates release security contract: %v", err)
	}

	mutant := cloneWorkflow(t, workflow)
	jobs(mutant)["release"].(map[string]interface{})["needs"] = []interface{}{"quality"}
	if err := validateReleaseJob(mutant); err == nil {
		t.Fatal("workflow without integration prerequisite passed validation")
	}

	mutant = cloneWorkflow(t, workflow)
	jobs(mutant)["release"].(map[string]interface{})["needs"] = []interface{}{"integration"}
	if err := validateReleaseJob(mutant); err == nil {
		t.Fatal("workflow without quality prerequisite passed validation")
	}
}

func TestVaultInstallerAuthenticatesManifestBeforeChecksumOrExtraction(t *testing.T) {
	workflow := loadWorkflow(t)
	if err := validateVaultInstaller(workflow); err != nil {
		t.Fatalf("CI workflow violates Vault installer contract: %v", err)
	}

	mutant := cloneWorkflow(t, workflow)
	installerRun(mutant)["run"] = strings.Replace(installerScript(t, mutant), "gpg", "not-gpg", 1)
	if err := validateVaultInstaller(mutant); err == nil {
		t.Fatal("workflow without manifest signature verification passed validation")
	}
}

func loadWorkflow(t *testing.T) map[string]interface{} {
	t.Helper()
	contents, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]interface{}
	if err := yaml.Unmarshal(contents, &workflow); err != nil {
		t.Fatalf("parse workflow YAML: %v", err)
	}
	return workflow
}

func cloneWorkflow(t *testing.T, workflow map[string]interface{}) map[string]interface{} {
	t.Helper()
	contents, err := yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]interface{}
	if err := yaml.Unmarshal(contents, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func validateReleaseJob(workflow map[string]interface{}) error {
	release, ok := jobs(workflow)["release"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("release job is missing")
	}
	if !hasExactNeeds(release["needs"], "quality", "integration") {
		return fmt.Errorf("release must need quality and integration")
	}
	return nil
}

func validateVaultInstaller(workflow map[string]interface{}) error {
	script := installerScriptValue(workflow)
	if !strings.Contains(script, hashicorpKeyURL) || !strings.Contains(script, "vault_2.2.1_SHA256SUMS.sig") {
		return fmt.Errorf("installer does not retrieve HashiCorp's signed checksum manifest")
	}
	if !strings.Contains(script, trustedPrimaryKey) || !strings.Contains(script, trustedSigningKey) {
		return fmt.Errorf("installer does not pin HashiCorp's primary and signing key fingerprints")
	}
	verifyAt := strings.Index(script, "gpg")
	checksumAt := strings.Index(script, "sha256sum")
	extractAt := strings.Index(script, "unzip")
	if verifyAt < 0 || checksumAt < 0 || extractAt < 0 || verifyAt > checksumAt || verifyAt > extractAt {
		return fmt.Errorf("manifest authentication does not precede checksum verification and extraction")
	}
	if !strings.Contains(script, "VALIDSIG") {
		return fmt.Errorf("installer does not fail closed on an untrusted signature")
	}
	return nil
}

func jobs(workflow map[string]interface{}) map[string]interface{} {
	return workflow["jobs"].(map[string]interface{})
}

func installerRun(workflow map[string]interface{}) map[string]interface{} {
	steps := jobs(workflow)["integration"].(map[string]interface{})["steps"].([]interface{})
	for _, step := range steps {
		step := step.(map[string]interface{})
		if step["name"] == "Download and verify Vault 2.2.1" {
			return step
		}
	}
	panic("Vault installer step is missing")
}

func installerScript(t *testing.T, workflow map[string]interface{}) string {
	t.Helper()
	return installerScriptValue(workflow)
}

func installerScriptValue(workflow map[string]interface{}) string {
	return installerRun(workflow)["run"].(string)
}

func hasExactNeeds(value interface{}, expected ...string) bool {
	needs, ok := value.([]interface{})
	if !ok || len(needs) != len(expected) {
		return false
	}
	for _, expectedNeed := range expected {
		found := false
		for _, need := range needs {
			if need == expectedNeed {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestVaultInstallerStopsBeforeChecksumAndExtractionOnSignatureFailure(t *testing.T) {
	workflow := loadWorkflow(t)
	script := installerScript(t, workflow)
	if !strings.Contains(script, "VALIDSIG") {
		t.Skip("signature-verifying installer does not exist yet")
	}

	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	writeStub(t, bin, "dpkg", "echo amd64")
	writeStub(t, bin, "curl", "exit 0")
	writeStub(t, bin, "gpg", "echo gpg >> \"$TEST_COMMAND_LOG\"; exit 1")
	writeStub(t, bin, "sha256sum", "echo sha256sum >> \"$TEST_COMMAND_LOG\"")
	writeStub(t, bin, "unzip", "echo unzip >> \"$TEST_COMMAND_LOG\"")

	command := exec.Command("bash", "-c", script)
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "RUNNER_TEMP="+t.TempDir(), "TEST_COMMAND_LOG="+logPath)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("installer accepted a failed signature verification: %s", output)
	}
	contents, _ := os.ReadFile(logPath)
	if strings.Contains(string(contents), "sha256sum") || strings.Contains(string(contents), "unzip") {
		t.Fatalf("installer continued after signature failure: %s", contents)
	}
}

func writeStub(t *testing.T, directory, name, body string) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatalf("write %s stub: %v", name, err)
	}
}
