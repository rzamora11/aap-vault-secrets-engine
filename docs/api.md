# API reference

All paths below are relative to the mount path, shown as `aap/` in examples.

## Configuration: `aap/config`

| Operation | Result |
| --- | --- |
| `write` | Validates and replaces the connection configuration. |
| `read` | Returns non-sensitive configuration metadata. |
| `delete` | Removes the configuration. |

Configuration reads redact `issuer_token` and `ca_cert`. A missing configuration prevents credential issuance and lease revocation until configuration is restored.

## Roles: `aap/roles/<name>`

| Operation | Result |
| --- | --- |
| `write` | Validates and replaces a role. |
| `read` | Returns `scope`, `ttl`, `max_ttl`, and `description_prefix`. |
| `delete` | Removes the role. |
| `list aap/roles` | Lists configured role names. |

Deleting a role prevents later credential reads for that role. It does not prevent revocation of leases already issued under it.

## Credentials: `aap/creds/<name>`

`read` creates an AAP child token through one upstream `POST /api/gateway/v1/tokens/` request. The response includes:

| Field | Meaning |
| --- | --- |
| `token` | Generated AAP bearer token. |
| `host` | Configured AAP gateway origin. |
| `expires_at` | Upstream token expiry in RFC 3339 format. |

The response also has a nonrenewable Vault lease. Its TTL is capped at `min(role ttl, role max_ttl, upstream expiry - now - 60 seconds)`. Request another credential when the lease expires.

Example retrieval is intentionally secret-bearing:

```sh
vault read aap/creds/automation-reader
```

Run it only where the output can go directly to the intended consumer. The `token` field is not safe for terminal capture, CI logs, Terraform state, or plan files.

## Error behavior and safety boundaries

- Invalid roles, a missing configuration, and unsafe gateway origins fail before an upstream request.
- Gateway responses accept one JSON value no larger than 1 MiB. Raw upstream response bodies are not returned in errors.
- Token IDs must be positive ASCII JSON integers. Invalid IDs do not reach the revocation endpoint.
- Revocation treats any 2xx response and 404 as success. Other responses remain visible as failures.
- If a successful issue response has a known token ID but unusable credential data, the plugin makes one best-effort cleanup delete. A cleanup failure is not hidden, but the primary issuance error remains the reported error.
- A failed or uncertain upstream `POST` is never retried. An unknown outcome can leave an upstream token orphaned; investigate the AAP gateway and issued-token records before attempting manual cleanup.
