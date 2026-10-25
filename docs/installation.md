# Installation

## Build and register the plugin

Build the plugin with Go 1.27.3:

```sh
make build
```

Install `bin/vault-plugin-secrets-aap` in the `plugin_directory` configured on every Vault node. The command supplied to Vault is the binary name, so the file must have that name in the plugin directory.

Calculate the checksum of the exact installed binary, then register it:

```sh
SHA256=$(sha256sum /path/to/plugin_directory/vault-plugin-secrets-aap | cut -d ' ' -f1)

vault plugin register \
  -sha256="$SHA256" \
  -command=vault-plugin-secrets-aap \
  secret vault-plugin-secrets-aap
```

Enable one mount:

```sh
vault secrets enable \
  -path=aap \
  -plugin-name=vault-plugin-secrets-aap \
  plugin
```

The plugin stores one AAP connection configuration per mount. A mount supports one issuer identity. Use separate mounts when environments or tenants need separate issuer identities.

## Future release archives

Published artifacts do not exist yet. Once a canonical-repository tag in the form `vX.Y.Z` is published, obtain its archive and `checksums.txt` from that release, then verify both before installation:

```sh
sha256sum --check --ignore-missing checksums.txt
tar -xzf vault-plugin-secrets-aap_vX.Y.Z_linux_amd64.tar.gz
sha256sum vault-plugin-secrets-aap
```

The archive checksum in `checksums.txt` verifies the archive. Vault registration requires the checksum of the extracted plugin binary. These are different hashes.

The release workflow also produces a checksum attestation for `dist/checksums.txt`. Verify it against the release repository and tag before trusting a published artifact:

```sh
gh attestation verify checksums.txt \
  --repo rzamora11/aap-vault-secrets-engine
```

Choose the archive matching the host architecture. The release configuration targets Linux `amd64` and `arm64` only. Do not claim a package for another operating system unless a published release contains it.
