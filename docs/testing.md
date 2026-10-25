# Testing

Run the repository checks from the project root:

```sh
make check
make vulncheck
make integration
make release-check
```

`make check` runs formatting, module verification, tidy verification, unit tests, race tests, vet, and a plugin build. Individual targets are `unit`, `race`, `integration`, `fmt-check`, `vet`, `mod-verify`, `tidy-check`, `vulncheck`, and `release-check`.

The integration suite starts a real local Vault process and uses a stateful HTTP fixture in place of AAP:

```sh
go test -tags=integration ./test/integration
```

Set `VAULT_BINARY` to choose the Vault executable. Set `VAULT_PLUGIN_BINARY` to test an already built or extracted plugin binary. `VAULT_INTEGRATION_ALLOW_SKIP=1` permits a local skip only when Vault is unavailable. Do not use that setting in CI.

No genuine AAP credential is required for the test suite. The HTTP fixture exercises the gateway contract and token lifecycle, but it is not validation against a live AAP deployment.

Before audit, the full unit and race suite reported 57 passing tests, along with vet, module, tidy, and `govulncheck` checks with no reported findings. Those results are evidence for that run, not a universal security guarantee.
