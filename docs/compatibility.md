# Compatibility and evidence

The engine implements the AAP platform-gateway token schema used by AAP 2.7 documentation. The project has not established a general live-AAP compatibility claim. Validate the gateway behavior, service-identity permissions, and revocation semantics in the target AAP deployment before production use.

Local lifecycle testing ran against real Vault 2.2.0 and 2.2.1 on Linux `amd64`. The Vault 2.2.1 run executed all five lifecycle tests with an extracted snapshot plugin archive in 19.670 seconds.

The release configuration cross-compiles Linux `amd64` and `arm64`. Native Linux `arm64` execution was not run locally. CI is configured to run the integration suite on `ubuntu-24.04-arm`, but no remote CI execution is claimed here.

No Darwin or Windows package is configured.

The Go module is `github.com/rzamora11/aap-vault-secrets-engine`, uses Go 1.27.3, Vault API 1.23.0, and Vault SDK 0.26.0. Two indirect metrics dependencies remain at `github.com/armon/go-metrics` 0.4.1 and `github.com/hashicorp/go-metrics` 0.6.1 because the upstream Vault SDK requires them. This does not establish that every module-graph node is the newest available version or that all dependencies meet a universal security target.
