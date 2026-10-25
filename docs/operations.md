# Operations

## Before changing or deleting configuration

**Drain active leases before any gateway endpoint, issuer identity, TLS certificate, CA, or configuration replacement or deletion.** This is an operational requirement documented here; the plugin does not enforce it.

Active leases need the current configuration to revoke their upstream AAP tokens. Deleting or replacing configuration while leases remain can make revocation fail. Issuer token rotation under the same identity must not be assumed to retain cleanup authority: verify that the replacement token can delete tokens created by the previous token before changing Vault configuration.

Run these read-only checks first:

```sh
set -euo pipefail

vault list aap/roles
vault read aap/config
```

Inventory active Vault leases for the mount using your approved Vault operator procedure. Do not paste credential-read output into that inventory. Revoke or let every active lease expire, then verify that no active lease still requires the current AAP connection.

Only after the drain is confirmed should an operator change the issuer, gateway, TLS settings, custom CA, or delete `aap/config`. Record the drain result and the authority check in the change record.

## Rotation runbook

1. Confirm the replacement issuer identity has only the intended AAP permissions.
2. Confirm it can revoke a non-production token created under the current identity, where the AAP authorization model permits that test.
3. Drain active Vault leases.
4. Update the configuration through the approved secret-input procedure described in [Configuration](configuration.md).
5. Issue one controlled credential and revoke its Vault lease. Confirm the upstream token is removed.
6. Restore normal credential reads only after the controlled revoke succeeds.

Do not remove the old issuer identity until the drain and controlled revoke complete.

## Role deletion

Deleting a role stops new reads but does not stop revocation of leases it already issued. Drain or revoke those leases before deleting a role so operators can account for outstanding tokens.

## Incident response

For a suspected issuer-token disclosure, stop granting new workload access, rotate the issuer through the runbook above, and inspect both Vault audit records and AAP token activity. Do not place token values in incident notes or logs.

An upstream issue request with an unknown outcome can create an orphaned token because the plugin does not retry `POST`. Investigate AAP records using the role's description prefix and time window. A retry by the client is a new issuance attempt, not proof that the first request failed.
