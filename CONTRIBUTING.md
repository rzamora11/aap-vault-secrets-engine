# Contributing

## Prerequisites

- Go 1.27.3
- GNU Make
- Vault 2.2.1 for the full local integration suite, or `VAULT_BINARY` pointing to an executable Vault binary

## Setup and checks

```sh
git clone https://github.com/rzamora11/aap-vault-secrets-engine.git
cd aap-vault-secrets-engine
make check
```

Run the lifecycle suite and release snapshot check when the change affects plugin behavior or packaging:

```sh
make integration
make release-check
```

The integration suite uses a real local Vault process and an HTTP AAP fixture. It does not require AAP credentials and does not prove compatibility with a live AAP deployment.

## Submit changes

Keep changes focused, include tests for behavior changes, and run the relevant Make targets before opening a pull request. Do not include generated credentials, issuer tokens, or credential-read output in commits, issues, or pull requests.
