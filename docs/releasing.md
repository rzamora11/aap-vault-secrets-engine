# Releasing

Releases are not published yet. The next planned tag is `v0.2.0`, but it has not been created, reserved, or published. For each release, merge the intended changes into `main` and pass the required checks, then a maintainer manually creates and pushes a semantic tag in the form `vX.Y.Z` from that merged commit. GoReleaser derives the release version from the tag; this project does not calculate a version from commit messages.

The tagged-release job runs only for `rzamora11/aap-vault-secrets-engine` and validates the tag format. Tag CI runs the quality checks and native Linux `amd64` and `arm64` integration jobs before GoReleaser 2.19.0 publishes Linux `amd64` and `arm64` tarballs containing the plugin binary and `LICENSE`, plus `checksums.txt`.

The workflow has minimal release permissions: `contents: write`, `id-token: write`, and `attestations: write`. The publisher passes GitHub Actions' built-in `github.token` to GoReleaser as `GITHUB_TOKEN`; no additional repository credential, PAT, or GitHub App is required. After publication, the workflow attests `dist/checksums.txt` with keyless provenance. Publication and provenance attestation are separate workflow steps, so they are not an atomic operation.

Before creating a tag, run:

```sh
make check
make integration
make release-check
```

After publication, verify the release archive checksum with `checksums.txt`, verify the attestation as shown in [Installation](installation.md), then calculate the extracted plugin binary checksum for Vault registration. Do not reuse the archive checksum as the Vault plugin checksum.

Until a tag and release assets exist, document source builds only. Do not publish a `latest` archive URL or claim release assets that do not yet exist.
