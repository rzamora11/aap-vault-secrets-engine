# Configuration

## AAP gateway connection

Write the connection at `aap/config`. The gateway URL must be an origin only: scheme and host, with no userinfo, query, fragment, or base path. HTTPS is required unless `allow_insecure_http=true` is explicitly set.

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `url` | Yes | None | AAP gateway origin, such as `https://aap.example.test`. |
| `issuer_token` | Yes | None | Dedicated AAP issuer token used to create and revoke child tokens. |
| `tls_skip_verify` | No | `false` | Disables certificate verification. Use only for a controlled test environment. |
| `ca_cert` | No | None | PEM-encoded CA certificate for a private AAP CA. |
| `allow_insecure_http` | No | `false` | Permits an HTTP origin. Use only for a controlled test environment. |

TLS verification is enabled by default. Prefer a custom CA over `tls_skip_verify`. HTTP requires the separate explicit opt-in.

`vault read aap/config` returns the URL, TLS settings, and booleans stating whether the issuer token and CA are configured. It never returns `issuer_token` or `ca_cert`.

The issuer token is a credential argument. Do not place its value in shell history, CI logs, or a command line visible to other local users. For example, arrange for an approved secret-input mechanism to create a mode-restricted JSON request file, then pass only its path to the Vault CLI:

```sh
vault write aap/config @/secure/path/aap-config.json
```

The JSON request includes `url` and `issuer_token`; it can also include the optional TLS fields. Remove the input file according to the operating procedure after Vault accepts it.

## Roles

Roles live at `aap/roles/<name>`. A write replaces the entire role, so include every field you intend to retain.

| Field | Default | Constraints |
| --- | --- | --- |
| `scope` | `write` | `read` or `write`; `write` includes read access. |
| `ttl` | `1h` | Positive and not greater than `max_ttl`. |
| `max_ttl` | `24h` | Positive. |
| `description_prefix` | `vault-aap` | Prefix used to identify issued AAP tokens. |

Example:

```sh
vault write aap/roles/automation-reader \
  scope=read \
  ttl=30m \
  max_ttl=1h \
  description_prefix=vault-aap
```

Roles limit OAuth scope and lease duration. They do not create independent AAP RBAC boundaries. AAP permissions come from the configured issuer identity.

## Least-privilege Vault policy

Give a workload read access only to its required credential role:

```hcl
path "aap/creds/automation-reader" {
  capabilities = ["read"]
}
```

Keep `config` and `roles` access in a separate operator policy.
