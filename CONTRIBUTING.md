# Contributing

Thanks for taking the time to contribute.

## Before opening a pull request

- Open an issue first for a substantial feature or behavior change.
- Do not include AAP tokens, Vault tokens, private URLs, or customer data in
  commits, issues, pull requests, test fixtures, or logs.
- Keep pull requests focused on one change.
- Add or update tests when changing plugin behavior.
- Update the README when changing a public path, field, response, or security
  assumption.

## Local checks

Run these checks before submitting a pull request:

```sh
make fmt
make test
make vet
make build
```

## Development principles

- Preserve Vault lease semantics. Credentials issued by this plugin must remain
  non-renewable unless the upstream AAP API can safely support renewal.
- Do not weaken TLS validation or request authentication defaults.
- Return useful errors without exposing issuer tokens or other credentials.
- Keep documentation clear about what the engine has been tested against.

## Reporting security issues

Do not report vulnerabilities in a public issue. Follow
[SECURITY.md](SECURITY.md) instead.
