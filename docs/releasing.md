# Releasing

Releases are not published yet. A future release begins with a human-created semantic tag in the canonical repository, using the form `vX.Y.Z`. Choose the version when the release is prepared; this project does not reserve a first release version.

The tagged-release job runs only for `rzamora11/aap-vault-secrets-engine` and validates the tag format. It uses GoReleaser 2.19.0 to publish Linux `amd64` and `arm64` tarballs containing the plugin binary and `LICENSE`, plus `checksums.txt`.

The workflow has minimal release permissions: `contents: write`, `id-token: write`, and `attestations: write`. It publishes through the GitHub Actions identity and attests `dist/checksums.txt` with keyless provenance.

Before creating a tag, run:

```sh
make check
make integration
make release-check
```

After publication, verify the release archive checksum with `checksums.txt`, verify the attestation as shown in [Installation](installation.md), then calculate the extracted plugin binary checksum for Vault registration. Do not reuse the archive checksum as the Vault plugin checksum.

Until a tag and release assets exist, document source builds only. Do not publish a `latest` archive URL or claim release assets that do not yet exist.
