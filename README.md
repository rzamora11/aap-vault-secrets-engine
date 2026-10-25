# AAP Vault secrets engine

`vault-plugin-secrets-aap` is an external HashiCorp Vault logical secrets engine. It creates short-lived AAP OAuth tokens through the AAP platform gateway and revokes them when their Vault leases end.

It is not a Terraform provider or a native HCP Terraform dynamic-credentials integration.

## Build from source

Requirements: Go 1.27.3 and a self-managed Vault deployment that permits external secret plugins.

```sh
git clone https://github.com/rzamora11/aap-vault-secrets-engine.git
cd aap-vault-secrets-engine
make build
```

The plugin binary is `bin/vault-plugin-secrets-aap`. Copy it to Vault's configured `plugin_directory` on every Vault node, calculate its SHA-256, then register and mount it:

```sh
SHA256=$(sha256sum bin/vault-plugin-secrets-aap | cut -d ' ' -f1)

vault plugin register \
  -sha256="$SHA256" \
  -command=vault-plugin-secrets-aap \
  secret vault-plugin-secrets-aap

vault secrets enable \
  -path=aap \
  -plugin-name=vault-plugin-secrets-aap \
  plugin
```

Configure a dedicated, least-privilege AAP issuer identity, create a role, then let workloads read only the role they need. See the [configuration guide](docs/configuration.md) and [API reference](docs/api.md).

## What a credential read does

`vault read aap/creds/<role>` sends one upstream `POST` to create an AAP token. The returned Vault lease is nonrenewable. Its lifetime is the smallest of the role `ttl`, role `max_ttl`, and the upstream token expiry minus 60 seconds.

The read output contains the generated bearer token. Treat that output as a secret: provide it directly to the intended consumer and do not write it to logs, CI output, Terraform state, or plan files.

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [API reference](docs/api.md)
- [Operations](docs/operations.md)
- [Security](docs/security.md)
- [Testing](docs/testing.md)
- [Compatibility and evidence](docs/compatibility.md)
- [Release process](docs/releasing.md)
- [Contributing](CONTRIBUTING.md)

## Releases

No release artifacts are published yet. Until a release exists, build from source. A future published release will provide Linux `amd64` and `arm64` archives, but an archive URL or a `latest` download URL must not be assumed before a tag is published.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
