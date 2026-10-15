# Vault secrets engine for Ansible Automation Platform

`vault-plugin-secrets-aap` is an external HashiCorp Vault logical secrets
engine. It creates a new AAP platform-gateway OAuth token whenever a caller
reads a Vault `creds` endpoint, and revokes that token when the Vault lease is
revoked or expires.

The MVP targets AAP 2.7 and newer platform-gateway deployments. It uses an AAP
**issuer token** as the provisioning identity: Vault uses that bearer token to
create a distinct child token for every credential request, then deletes the
child token when its Vault lease ends.

## Security model

The identity that owns the configured issuer token determines the generated
token's AAP RBAC. A Vault role cannot add AAP permissions; it selects only the
token scope (`read` or `write`) and the Vault lease lifetime. Create a
narrowly-permitted local service identity and issuer token per AAP environment
or tenant boundary. Never use an AAP administrator token.

The issuer token and CA certificate are held in Vault's seal-wrapped plugin
storage and are intentionally omitted from configuration reads. The plugin
verifies TLS by default. Set `tls_skip_verify=true` only for a non-production
test environment. Plaintext HTTP is rejected unless `allow_insecure_http=true`
is explicitly set for a test environment.

AAP controls the actual OAuth expiry system-wide. The plugin does not require
that setting to change: it calculates the lease as the smallest of the role
TTL, role maximum TTL, and the AAP-reported remaining lifetime less a one-minute
safety margin. If Vault cannot revoke a child token, the AAP expiry is the
fallback limit. The issuer token has its own lifecycle and must be rotated
before its AAP expiry; if it expires, Vault cannot issue or revoke child tokens.

Generated leases are deliberately non-renewable. Requesting a fresh secret
creates a fresh AAP token rather than extending an opaque upstream credential.

## API

| Path | Operations | Purpose |
| --- | --- | --- |
| `config` | read, write, delete | AAP platform gateway and protected issuer token |
| `roles/<name>` | read, write, delete | Token scope and Vault TTL policy |
| `roles` | list | List configured roles |
| `creds/<name>` | read | Create a leased OAuth token |

The `creds` response contains `token`, `host`, and `expires_at`. Consumers use
the token as `AAP_TOKEN` and the host as `AAP_HOST` with the `ansible/aap`
Terraform provider.

## Build

The project requires Go 1.23 or later and a Vault version compatible with the
plugin SDK declared in `go.mod`.

```sh
make test
make build
```

This creates `bin/vault-plugin-secrets-aap`.

## Local Vault registration

Place the plugin binary in the `plugin_directory` configured on every Vault
node. Register its SHA-256, then enable it as an external secret plugin:

```sh
SHA256=$(shasum -a 256 bin/vault-plugin-secrets-aap | cut -d ' ' -f1)
vault plugin register -sha256="$SHA256" -command=vault-plugin-secrets-aap secret vault-plugin-secrets-aap
vault secrets enable -path=aap -plugin-name=vault-plugin-secrets-aap plugin
```

## Configure and issue a token

```sh
vault write aap/config \
  url=https://aap.example.com \
  issuer_token='replace-me'

vault write aap/roles/terraform-operator \
  scope=write \
  ttl=1h \
  max_ttl=1h \
  description_prefix=vault-aap-terraform

vault read aap/creds/terraform-operator
```

The default role TTL is one hour; `ttl` and `max_ttl` accept Vault duration
syntax. The effective lease can be shorter if AAP returns an earlier expiry.

## Terraform delivery

Keep the engine runtime-neutral: acquire a lease immediately before the
Terraform run and inject its `token` into `AAP_TOKEN`. Do not persist the
generated response in Terraform state. For an HCP Terraform proof of concept,
using a Vault data source can demonstrate the integration, but it may persist
the token in state and is not the recommended production delivery method.

## Tests

Unit tests use an in-memory Vault backend and a fake AAP gateway. They cover:

- token creation and revocation with an AAP issuer bearer token;
- AAP expiry capping a one-hour Vault lease;
- configuration redaction;
- remote token revocation, including idempotent handling of AAP `404`.

An acceptance test against a real AAP 2.7 environment remains the next step.
