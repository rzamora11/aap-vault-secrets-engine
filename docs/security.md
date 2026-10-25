# Security model

The configured AAP issuer token is the authority used to create and revoke child tokens. Use a dedicated AAP service identity with only the rights needed for those operations. Do not configure an administrator token.

One mount has one issuer identity. Roles set token scope and lease duration, but they do not provide independent AAP RBAC. Use separate mounts and issuer identities where permissions must be isolated.

## Transport and storage

- Gateway URLs are restricted to an HTTP or HTTPS origin with no path, query, fragment, or userinfo.
- HTTPS certificate verification is enabled by default. Use `ca_cert` for a private CA. `tls_skip_verify` and `allow_insecure_http` are explicit test-environment opt-ins.
- Vault barrier encryption protects data stored by Vault. Separately, the backend's `SealWrapStorage` declaration requests [seal wrapping](https://developer.hashicorp.com/vault/docs/enterprise/sealwrap) for its supported storage paths when the deployment has the required Enterprise entitlement, a supporting seal, and seal wrapping enabled in the deployment configuration. A Community Vault deployment does not receive an additional seal-wrapping guarantee from this backend.
- Configuration reads redact the issuer token and custom CA.
- The plugin does not return raw AAP gateway error bodies.

## Credential handling

The result of `aap/creds/<role>` includes a bearer token. Do not send the output to logs, ticket attachments, CI output, Terraform state, or plan files. Limit Vault policies to the exact credential path a workload needs.

## Dependency advisory residual risk

The official [GO-2026-5932 advisory](https://vuln.go.dev/ID/GO-2026-5932.json), published 2026-07-07, covers the legacy `golang.org/x/crypto/openpgp` package in all versions and lists no fixed version. The current module graph includes `golang.org/x/crypto` 0.58.0, so the advisory remains present at the module level.

With Go 1.27.3, `govulncheck` 1.9.0 found zero affected reachable calls across the repository's three root packages in its analyzed build configuration. This advisory is neither patched nor suppressed. The normal `make vulncheck` gate remains enabled and will fail if it finds a new reachable vulnerability in that configuration.

Rodo accepted this residual risk for this pull request only. It is not a general endorsement of the dependency and does not guarantee security. Reassess it when the SDK or dependencies change, or when build tags, platforms, or other build configurations change. This focused work does not plan a dependency migration or fork.

## Vulnerability reports

This repository does not publish a maintainer email address or other private reporting channel. Do not disclose a suspected vulnerability, exploit, or credential in a public issue. If GitHub Private Vulnerability Reporting is enabled for this repository, use the repository security advisory form. Otherwise, contact the repository owner through an already established private channel.

Private Vulnerability Reporting is a repository setting. Its enablement has not been verified here.
