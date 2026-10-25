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

## Vulnerability reports

This repository does not publish a maintainer email address or other private reporting channel. Do not disclose a suspected vulnerability, exploit, or credential in a public issue. If GitHub Private Vulnerability Reporting is enabled for this repository, use the repository security advisory form. Otherwise, contact the repository owner through an already established private channel.

Private Vulnerability Reporting is a repository setting. Its enablement has not been verified here.
