/*
 * @spec-handoff
 * @interface validatePublisherEnvironment(map[string]interface{}) error
 * @behavior
 *   - The release job's Publish release archives step passes only GitHub's built-in token expression as GITHUB_TOKEN.
 *   - The GoReleaser child process receives GITHUB_TOKEN through that exact step environment.
 *   - Release gates and contents: write permission remain required.
 * @edge-cases
 *   - Missing, misplaced, or new-secret token bindings fail the workflow contract.
 * @see ../../.github/workflows/ci.yml
 */
package ci

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const publisherHelperMarker = "PUBLISHER_ENVIRONMENT_TEST_HELPER"

func TestReleasePublisherEnvironmentContract(t *testing.T) {
	workflow := loadWorkflow(t)
	status := runPublisherChild(t, publisherChildEnv(workflow))
	if status != "present" {
		t.Fatalf("publisher child GITHUB_TOKEN = %q; want present", status)
	}
	if err := validatePublisherEnvironment(workflow); err != nil {
		t.Fatalf("CI workflow violates publisher environment contract: %v", err)
	}
}
func TestPublisherEnvironmentAcceptsBuiltInTokenBindings(t *testing.T) {
	for _, expression := range []string{"${{ github.token }}", "${{ secrets.GITHUB_TOKEN }}"} {
		t.Run(expression, func(t *testing.T) {
			fixture := cloneWorkflow(t, loadWorkflow(t))
			publisherStepValue(fixture)["env"] = map[string]interface{}{"GITHUB_TOKEN": expression}
			if err := validatePublisherEnvironment(fixture); err != nil {
				t.Fatalf("valid built-in binding rejected: %v", err)
			}
			if status := runPublisherChild(t, publisherChildEnv(fixture)); status != "present" {
				t.Fatalf("publisher child GITHUB_TOKEN = %q; want present", status)
			}
		})
	}
}
func TestPublisherEnvironmentRejectsUnsafeBindings(t *testing.T) {
	newFixture := func(t *testing.T) map[string]interface{} {
		t.Helper()
		fixture := cloneWorkflow(t, loadWorkflow(t))
		publisherStepValue(fixture)["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		return fixture
	}
	cases := map[string]func(*testing.T, map[string]interface{}){
		"missing token": func(t *testing.T, workflow map[string]interface{}) {
			delete(publisherStepValue(workflow), "env")
		},
		"token on snapshot step": func(t *testing.T, workflow map[string]interface{}) {
			delete(publisherStepValue(workflow), "env")
			snapshotStepValue(workflow)["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"token on unrelated release step": func(t *testing.T, workflow map[string]interface{}) {
			delete(publisherStepValue(workflow), "env")
			releaseStepsValue(workflow)[0].(map[string]interface{})["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"new secret": func(t *testing.T, workflow map[string]interface{}) {
			publisherStepValue(workflow)["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ secrets.NEW_TOKEN }}"}
		},
		"action token input": func(t *testing.T, workflow map[string]interface{}) {
			publisherStepValue(workflow)["with"].(map[string]interface{})["token"] = "${{ github.token }}"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			mutate(t, fixture)
			if err := validatePublisherEnvironment(fixture); err == nil {
				t.Fatal("unsafe publisher token binding passed validation")
			}
		})
	}
}

func validatePublisherEnvironment(workflow map[string]interface{}) error {
	if err := validateReleaseJob(workflow); err != nil {
		return err
	}
	release, ok := jobs(workflow)["release"].(map[string]interface{})
	permissions, permissionsOK := release["permissions"].(map[string]interface{})
	if !ok || !permissionsOK || permissions["contents"] != "write" {
		return fmt.Errorf("release must retain contents: write permission")
	}
	if tokenEnv(workflow["env"]) || tokenEnv(release["env"]) {
		return fmt.Errorf("GITHUB_TOKEN must not be globally or job scoped")
	}
	step := publisherStepValue(workflow)
	if token, ok := step["with"].(map[string]interface{})["token"]; ok && token != nil {
		return fmt.Errorf("publisher action must not use a token input")
	}
	if !hasExactStringFields(step["env"], "GITHUB_TOKEN", "${{ github.token }}") && !hasExactStringFields(step["env"], "GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}") {
		return fmt.Errorf("publisher must receive only a built-in GITHUB_TOKEN binding")
	}
	for jobName, job := range jobs(workflow) {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}
		if tokenEnv(jobMap["env"]) {
			return fmt.Errorf("GITHUB_TOKEN must not be job scoped, found in %s", jobName)
		}
		for _, candidate := range jobSteps(jobMap) {
			isPublisher := jobName == "release" && candidate["name"] == step["name"]
			if !isPublisher && tokenEnv(candidate["env"]) {
				return fmt.Errorf("GITHUB_TOKEN must be scoped to release publisher, found in %s", jobName)
			}
		}
	}
	return nil
}

func publisherChildEnv(workflow map[string]interface{}) []string {
	step := publisherStepValue(workflow)
	env, _ := step["env"].(map[string]interface{})
	if _, ok := env["GITHUB_TOKEN"].(string); !ok {
		return nil
	}
	// GitHub Actions evaluates the expression before launching the action; this fixture proves only process-env propagation, never a live publish.
	return []string{"GITHUB_TOKEN=fixture-token"}
}

func runPublisherChild(t *testing.T, publisherEnv []string) string {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestPublisherEnvironmentChild$")
	command.Env = append([]string{publisherHelperMarker + "=1"}, publisherEnv...)
	output, err := command.CombinedOutput()
	if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 3 {
		return strings.TrimSpace(string(output))
	}
	if err != nil {
		t.Fatalf("run publisher child: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func TestPublisherEnvironmentChild(t *testing.T) {
	if os.Getenv(publisherHelperMarker) != "1" {
		return
	}
	if _, present := os.LookupEnv("GITHUB_TOKEN"); present {
		fmt.Print("present")
		os.Exit(0)
	}
	fmt.Print("absent")
	os.Exit(3)
}

func publisherStepValue(workflow map[string]interface{}) map[string]interface{} {
	for _, step := range releaseStepsValue(workflow) {
		stepMap := step.(map[string]interface{})
		if stepMap["name"] == "Publish release archives" {
			return stepMap
		}
	}
	panic("release publisher step is missing")
}

func releaseStepsValue(workflow map[string]interface{}) []interface{} {
	return jobs(workflow)["release"].(map[string]interface{})["steps"].([]interface{})
}

func snapshotStepValue(workflow map[string]interface{}) map[string]interface{} {
	for _, step := range jobSteps(jobs(workflow)["release-snapshot"].(map[string]interface{})) {
		if step["name"] == "Build release archives without publishing" {
			return step
		}
	}
	panic("snapshot publisher step is missing")
}

func jobSteps(job map[string]interface{}) []map[string]interface{} {
	steps, _ := job["steps"].([]interface{})
	result := make([]map[string]interface{}, 0, len(steps))
	for _, step := range steps {
		result = append(result, step.(map[string]interface{}))
	}
	return result
}

func hasExactStringFields(value interface{}, key, expected string) bool {
	fields, ok := value.(map[string]interface{})
	return ok && len(fields) == 1 && fields[key] == expected
}

func tokenEnv(value interface{}) bool {
	fields, _ := value.(map[string]interface{})
	_, found := fields["GITHUB_TOKEN"]
	return found
}
