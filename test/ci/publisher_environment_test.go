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

const (
	publisherName   = "Publish release archives"
	publisherAction = "goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de"
	publisherArgs   = "release --clean"
)

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
	for _, expression := range []string{"${{ github.token }}", "${{ secrets.GITHUB_TOKEN }}", "${{  github.token  }}"} {
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
		"custom publisher action": func(t *testing.T, workflow map[string]interface{}) {
			publisherStepValue(workflow)["uses"] = "example.invalid/custom-release-action@deadbeef"
		},
		"duplicate publisher name carries token": func(t *testing.T, workflow map[string]interface{}) {
			releaseStepsValue(workflow)[0].(map[string]interface{})["name"] = "Publish release archives"
			releaseStepsValue(workflow)[0].(map[string]interface{})["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"token on unrelated job step": func(t *testing.T, workflow map[string]interface{}) {
			jobSteps(jobs(workflow)["quality"].(map[string]interface{}))[0]["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"global token": func(t *testing.T, workflow map[string]interface{}) {
			workflow["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"release job token": func(t *testing.T, workflow map[string]interface{}) {
			jobs(workflow)["release"].(map[string]interface{})["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}"}
		},
		"publisher has extra secret": func(t *testing.T, workflow map[string]interface{}) {
			publisherStepValue(workflow)["env"] = map[string]interface{}{"GITHUB_TOKEN": "${{ github.token }}", "OTHER_SECRET": "${{ secrets.OTHER_SECRET }}"}
		},
		"snapshot publisher arguments": func(t *testing.T, workflow map[string]interface{}) {
			publisherStepValue(workflow)["with"].(map[string]interface{})["args"] = "release --snapshot --clean"
		},
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
	var violations []string
	if err := validateReleaseJob(workflow); err != nil {
		violations = append(violations, err.Error())
	}
	release, ok := jobs(workflow)["release"].(map[string]interface{})
	permissions, permissionsOK := release["permissions"].(map[string]interface{})
	if !ok || !permissionsOK || permissions["contents"] != "write" {
		violations = append(violations, "release must retain contents: write permission")
	}
	if tokenEnv(workflow["env"]) || tokenEnv(release["env"]) {
		violations = append(violations, "GITHUB_TOKEN must not be globally or job scoped")
	}

	var namedPublishers []map[string]interface{}
	var publishers []map[string]interface{}
	for jobName, job := range jobs(workflow) {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}
		if tokenEnv(jobMap["env"]) {
			violations = append(violations, fmt.Sprintf("GITHUB_TOKEN must not be job scoped, found in %s", jobName))
		}
		for _, candidate := range jobSteps(jobMap) {
			isNamedPublisher := jobName == "release" && candidate["name"] == publisherName
			isPublisher := isNamedPublisher && isPublisherIdentity(candidate)
			if isNamedPublisher {
				namedPublishers = append(namedPublishers, candidate)
			}
			if isPublisher {
				publishers = append(publishers, candidate)
			}
			if !isPublisher && tokenEnv(candidate["env"]) {
				violations = append(violations, fmt.Sprintf("GITHUB_TOKEN must be scoped to release publisher, found in %s", jobName))
			}
		}
	}
	if len(namedPublishers) != 1 {
		violations = append(violations, "release must contain exactly one named publisher step")
	}
	if len(publishers) != 1 {
		violations = append(violations, "release must contain exactly one pinned GoReleaser publisher")
	}
	if len(publishers) == 1 {
		step := publishers[0]
		if token, ok := step["with"].(map[string]interface{})["token"]; ok && token != nil {
			violations = append(violations, "publisher action must not use a token input")
		}
		if !hasBuiltInTokenBinding(step["env"]) {
			violations = append(violations, "publisher must receive only a built-in GITHUB_TOKEN binding")
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("%s", strings.Join(violations, "; "))
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
		if stepMap["name"] == publisherName {
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

func isPublisherIdentity(step map[string]interface{}) bool {
	with, ok := step["with"].(map[string]interface{})
	return ok && step["uses"] == publisherAction && normalizedString(with["args"]) == publisherArgs
}

func hasBuiltInTokenBinding(value interface{}) bool {
	fields, ok := value.(map[string]interface{})
	if !ok || len(fields) != 1 {
		return false
	}
	token, ok := fields["GITHUB_TOKEN"].(string)
	if !ok {
		return false
	}
	return normalizedString(token) == "${{ github.token }}" || normalizedString(token) == "${{ secrets.GITHUB_TOKEN }}"
}

func normalizedString(value interface{}) string {
	stringValue, _ := value.(string)
	return strings.Join(strings.Fields(stringValue), " ")
}

func tokenEnv(value interface{}) bool {
	fields, _ := value.(map[string]interface{})
	_, found := fields["GITHUB_TOKEN"]
	return found
}
