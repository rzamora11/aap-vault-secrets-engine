# AAP Vault secrets engine

[![CI](https://github.com/rzamora11/aap-vault-secrets-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/rzamora11/aap-vault-secrets-engine/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/roman-zamora/aap-vault-secrets-engine.svg)](https://pkg.go.dev/github.com/roman-zamora/aap-vault-secrets-engine)

`vault-plugin-secrets-aap` is a community Vault secret plugin that issues and
revokes short-lived OAuth tokens for Red Hat Ansible Automation Platform (AAP).
It gives Terraform, CI systems, and other Vault clients a fresh AAP token for
each credential request instead of distributing a shared long-lived token.

> [!WARNING]
> This is an MVP and a community project. It is not developed, supported, or
> endorsed by HashiCorp or Red Hat. Test it outside production before relying
> on it. The engine has been tested against AAP 2.7 (Automation Controller
> 4.8.0) and Vault Self-Managed. Compatibility with other releases needs validation.

## Contents

- [How it works](#how-it-works)
- [What the MVP supports](#what-the-mvp-supports)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Access policy](#access-policy)
- [API reference](#api-reference)
- [Terraform Actions direction](#terraform-actions-direction)
- [Security and operations](#security-and-operations)
- [Roadmap](#roadmap)
- [License](#license)

## How it works

```text
Vault client
  -> read aap/creds/<role>
  -> Vault plugin uses a protected AAP issuer token
  -> AAP gateway creates a unique child token
  -> Vault returns the child token with a non-renewable lease
  -> Vault revokes the child token when the lease ends or is revoked
```

The plugin uses AAP's platform-gateway token endpoint. The configured issuer
token is the provisioning identity. Vault keeps it in seal-wrapped plugin
storage and uses it only to create and revoke child tokens.

## What the MVP supports

- AAP 2.7 platform-gateway token creation and revocation.
- One unique AAP bearer token per `creds` read.
- Vault leases that are non-renewable and default to one hour.
- AAP `read` and `write` token scopes.
- Lease revocation that deletes the issued token in AAP.
- TLS verification by default, optional custom CA, and explicit opt-in for
  insecure HTTP or skipped certificate verification.

The effective Vault lease is the shortest of the role TTL, the role maximum
TTL, and the AAP token's remaining lifetime minus one minute. The engine does
not require a change to AAP's global token lifetime.

## Requirements

- A self-managed Vault deployment that can register and execute external
  plugins. Vault treats this as an external `secret` plugin.
- Go 1.23.3 or later to build from source.
- An AAP instance that exposes the platform gateway token endpoint.
- A dedicated AAP service identity with permission to create and delete its
  own child tokens.

The engine needs network access from every Vault node to the AAP gateway.

## Quick start

### 1. Build the plugin

```sh
git clone https://github.com/rzamora11/aap-vault-secrets-engine.git
cd aap-vault-secrets-engine
make build
```

The binary is written to `bin/vault-plugin-secrets-aap`.

### 2. Register and enable it

Copy the binary to the `plugin_directory` configured on every Vault node. Then
register its checksum and enable it at the `aap/` mount path:

```sh
SHA256=$(shasum -a 256 bin/vault-plugin-secrets-aap | cut -d ' ' -f1)

vault plugin register \
  -sha256="$SHA256" \
  -command=vault-plugin-secrets-aap \
  secret vault-plugin-secrets-aap

vault secrets enable \
  -path=aap \
  -plugin-name=vault-plugin-secrets-aap \
  plugin
```

For a local development server, start Vault with `-dev-plugin-dir=./bin` after
building the binary.

### 3. Configure the AAP connection

Create a dedicated AAP service identity and issuer token before this step. Do
not configure an AAP administrator token.

```sh
vault write aap/config \
  url=https://aap.example.com \
  issuer_token='replace-with-aap-issuer-token'
```

The plugin does not return `issuer_token` or `ca_cert` from `aap/config`.

### 4. Create an issuing role

```sh
vault write aap/roles/terraform-operator \
  scope=write \
  ttl=1h \
  max_ttl=1h \
  description_prefix=vault-aap-terraform
```

`write` includes read access in AAP. Use `read` when a client only needs to
inspect AAP objects.

### 5. Request and revoke credentials

```sh
vault read aap/creds/terraform-operator
```

The response contains `token`, `host`, and `expires_at`, plus a Vault lease ID.
To revoke the AAP child token before the lease ends:

```sh
vault lease revoke aap/creds/terraform-operator/<lease-id>
```

Use the lease ID returned by the `vault read` command. Vault also attempts the
same revocation when the lease expires.

## Access policy

Give workloads permission only to read the specific credential role they need:

```hcl
path "aap/creds/terraform-operator" {
  capabilities = ["read"]
}
```

Keep configuration and role management in a separate administrator policy. A
role controls only scope and lease duration. AAP RBAC comes from the service
identity that owns the configured issuer token, so use a separate issuer token
for each meaningful tenant or environment boundary.

## API reference

### `aap/config`

| Field | Required | Description |
| --- | --- | --- |
| `url` | Yes | AAP platform gateway base URL. HTTPS is required by default. |
| `issuer_token` | Yes | AAP bearer token used to issue and revoke child tokens. |
| `tls_skip_verify` | No | Skip TLS certificate validation. Defaults to `false`. Test use only. |
| `ca_cert` | No | PEM-encoded CA certificate for the AAP gateway. |
| `allow_insecure_http` | No | Permit an HTTP URL. Defaults to `false`. Test use only. |

Reading the path returns connection metadata and booleans that indicate whether
sensitive values are configured. It never returns the issuer token or CA
certificate.

### `aap/roles/<name>`

| Field | Default | Description |
| --- | --- | --- |
| `scope` | `write` | AAP OAuth scope: `read` or `write`. |
| `ttl` | `1h` | Requested lifetime for generated credentials. |
| `max_ttl` | `24h` | Maximum lifetime for generated credentials. |
| `description_prefix` | `vault-aap` | Prefix used to identify Vault-issued tokens in AAP. |

`ttl` must be positive and cannot exceed `max_ttl`.

### `aap/creds/<name>`

Reads the named role, creates a child AAP token, and returns a non-renewable
Vault lease. The response data contains:

| Field | Description |
| --- | --- |
| `token` | The generated AAP bearer token. |
| `host` | The configured AAP base URL. |
| `expires_at` | AAP-reported expiry in RFC 3339 format. |

Revoking the Vault lease deletes the child token through the AAP gateway. AAP's
own token expiry remains the final fallback if AAP is unavailable during Vault
revocation.

## Terraform Actions direction

This MVP was built to validate the AAP credential lifecycle required by a
potential native dynamic credentials broker for Terraform Actions in the
[`ansible/aap`](https://registry.terraform.io/providers/ansible/aap/latest/docs)
provider on HCP Terraform.

The engine proves that a broker can issue a unique AAP token for a Terraform
operation and revoke it when the Vault lease ends. It is not a native HCP
Terraform dynamic credentials integration today. HCP Terraform does not
currently inject credentials from an arbitrary custom Vault secret engine into
the AAP provider.

For any non-native integration, acquire a credential immediately before the
Terraform operation and pass the returned token as `AAP_TOKEN`. Do not put the
generated token in Terraform configuration, plan files, or state. A Vault data
source can demonstrate the flow, but it can persist the token in Terraform
state and is therefore test-only.

## Security and operations

- The issuer token is the most sensitive dependency. It should belong to a
  minimally privileged, non-administrator AAP service identity.
- Rotate the issuer token before its AAP expiry. If it expires, the engine
  cannot issue or revoke child tokens.
- Use a separate issuer identity per environment or tenant boundary. This is
  how you keep AAP permissions separate in the current MVP.
- Vault uses normal TLS validation unless an operator explicitly disables it.
- Audit both Vault lease events and AAP token activity.
- Run the plugin binary and configure its checksum according to Vault's
  [external plugin documentation](https://developer.hashicorp.com/vault/docs/plugins).

## Roadmap

- Additional AAP version and deployment validation.
- Per-role issuer identities and AAP RBAC validation.
- Metrics and operational guidance.
- Release automation, signed artifacts, and compatibility testing.
- A production-safe Terraform delivery pattern that avoids credential material
  entering Terraform state.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
