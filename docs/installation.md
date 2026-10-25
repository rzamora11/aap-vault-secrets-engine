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

Published artifacts do not exist yet. Once a canonical-repository tag in the form `vX.Y.Z` is published, download its archive and `checksums.txt`. Authenticate the checksum manifest before extracting or executing an archive. For tag `v1.2.3`, the Linux amd64 archive name is `vault-plugin-secrets-aap_1.2.3_linux_amd64.tar.gz`.

```sh
set -euo pipefail

TAG=vX.Y.Z
ARCHIVE="vault-plugin-secrets-aap_${TAG#v}_linux_amd64.tar.gz"
REPOSITORY=rzamora11/aap-vault-secrets-engine

gh release download "$TAG" --repo "$REPOSITORY" \
  --pattern checksums.txt \
  --pattern "$ARCHIVE"

gh attestation verify checksums.txt \
  --repo "$REPOSITORY" \
  --source-ref "refs/tags/$TAG" \
  --signer-workflow "rzamora11/aap-vault-secrets-engine/.github/workflows/ci.yml"

expected_archive_line="$(awk -v archive="$ARCHIVE" '$2 == archive { count++; line = $0 } END { if (count != 1) exit 1; print line }' checksums.txt)"
printf '%s\n' "$expected_archive_line" | sha256sum --check --strict --status -

tar -xzf "$ARCHIVE" vault-plugin-secrets-aap
PLUGIN_SHA256="$(sha256sum vault-plugin-secrets-aap | cut -d ' ' -f1)"

vault plugin register \
  -sha256="$PLUGIN_SHA256" \
  -command=vault-plugin-secrets-aap \
  secret vault-plugin-secrets-aap
```

The attested `checksums.txt` authenticates the archive hash. The archive hash verifies the downloaded archive before extraction. Vault registration requires the checksum of the extracted plugin binary. These are different hashes. The attestation command binds the manifest to the canonical repository, expected tag ref, and release workflow.

Choose the archive matching the host architecture. The release configuration targets Linux `amd64` and `arm64` only. Do not claim a package for another operating system unless a published release contains it.
