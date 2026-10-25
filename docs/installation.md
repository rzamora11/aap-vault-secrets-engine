# Installation

## Build the plugin

Build the plugin with Go 1.27.3:

```sh
make build
```

Continue with [Install and register the plugin](#install-and-register-the-plugin). Do not register the build-host file directly: Vault does not upload a plugin binary when it registers a catalog entry.

## Install and register the plugin

The plugin binary must be installed in the `plugin_directory` configured on **every Vault server** before the catalog is registered. Set the configured directory, file ownership, permissions, and the transfer method for the target deployment. A build or downloaded archive on an administrator workstation is not an installation on the Vault servers.

For each Vault server, copy the verified binary to a temporary path on that server, then install it under the required name. Replace the placeholders with the configured plugin directory and the Vault service account for that server:

```sh
install -o <vault-user> -g <vault-group> -m 0755 \
  /path/on/this-server/to/verified/vault-plugin-secrets-aap \
  /path/to/configured/plugin_directory/vault-plugin-secrets-aap

sha256sum /path/to/configured/plugin_directory/vault-plugin-secrets-aap
```

Record the checksum from each server. Do not register the plugin until every server reports the same checksum for its exact installed file. Run the following catalog-registration command once, against the Vault cluster, only after that comparison succeeds. Use a semantic version that identifies the installed build; for a release archive, use the tag without its leading `v`.

```sh
PLUGIN_SHA256=<checksum-reported-by-every-Vault-server>
PLUGIN_VERSION=<semantic-version>

vault plugin register \
  -sha256="$PLUGIN_SHA256" \
  -version="$PLUGIN_VERSION" \
  -command=vault-plugin-secrets-aap \
  secret vault-plugin-secrets-aap
```

`vault plugin register` records catalog metadata. It does not copy the executable into a Vault server's plugin directory. Registering before every server has the same installed executable can leave a cluster unable to run the registered plugin.

Enable one mount:

```sh
vault secrets enable \
  -path=aap \
  -plugin-name=vault-plugin-secrets-aap \
  plugin
```

The plugin stores one AAP connection configuration per mount. A mount supports one issuer identity. Use separate mounts when environments or tenants need separate issuer identities.

## Future release archives

Published artifacts do not exist yet. Once a canonical-repository tag in the form `vX.Y.Z` is published, download its archive and `checksums.txt`. Authenticate the downloaded archive before extracting or executing it. For tag `v1.2.3`, the Linux amd64 archive name is `vault-plugin-secrets-aap_1.2.3_linux_amd64.tar.gz`.

```sh
set -euo pipefail

TAG=vX.Y.Z
ARCHIVE="vault-plugin-secrets-aap_${TAG#v}_linux_amd64.tar.gz"
REPOSITORY=rzamora11/aap-vault-secrets-engine

gh release download "$TAG" --repo "$REPOSITORY" \
  --pattern checksums.txt \
  --pattern "$ARCHIVE"

gh attestation verify "$ARCHIVE" \
  --repo "$REPOSITORY" \
  --source-ref "refs/tags/$TAG" \
  --signer-workflow "rzamora11/aap-vault-secrets-engine/.github/workflows/ci.yml"

expected_archive_line="$(awk -v archive="$ARCHIVE" '$2 == archive { count++; line = $0 } END { if (count != 1) exit 1; print line }' checksums.txt)"
printf '%s\n' "$expected_archive_line" | sha256sum --check --strict --status -

tar -xzf "$ARCHIVE" vault-plugin-secrets-aap
```

After extracting, follow [Install and register the plugin](#install-and-register-the-plugin): copy this verified `vault-plugin-secrets-aap` file to every Vault server, install it in each configured plugin directory, compare the installed-file checksums, and register once with `PLUGIN_VERSION="${TAG#v}"`. Do not use the archive checksum or the extracted-file checksum as the registration checksum. The registration checksum comes from the identical installed files on the Vault servers.

The attestation authenticates the downloaded archive. `checksums.txt` is a supplemental archive-hash check. The extracted file is the verified input to each server installation. Vault registration requires the checksum of the installed plugin binary after that copy. These are distinct hashes. The attestation command binds the archive to the canonical repository, expected tag ref, and release workflow.

Choose the archive matching the host architecture. The release configuration targets Linux `amd64` and `arm64` only. Do not claim a package for another operating system unless a published release contains it.
