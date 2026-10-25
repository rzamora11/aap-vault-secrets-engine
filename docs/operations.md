# Operations

## Before changing or deleting configuration

**Drain active leases before any gateway endpoint, issuer identity, TLS certificate, CA, or configuration replacement or deletion.** This is an operational requirement documented here; the plugin does not enforce it.

Active leases need the current configuration to revoke their upstream AAP tokens. Deleting or replacing configuration while leases remain can make revocation fail. Issuer token rotation under the same identity must not be assumed to retain cleanup authority: verify that the replacement token can delete tokens created by the previous token before changing Vault configuration. Follow the [rotation runbook](#rotation-runbook) for any configuration change that affects issuance or revocation.

Run these read-only checks first:

```sh
set -euo pipefail

vault list aap/roles
vault read aap/config
```

Do not treat an empty Vault lease inventory as proof that AAP has no token from an earlier request with an unknown outcome. Investigate those possible orphaned tokens in AAP records as described in [Incident response](#incident-response).

## Rotation runbook

1. Freeze new credential reads at the workload access boundary. Preserve the mount, its current configuration, and the current issuer identity and its ability to revoke existing tokens. This is an operator procedure, not a plugin-enforced guard.
2. Wait for every in-flight credential issuance request to complete. Investigate any request with an unknown outcome as a possible orphaned AAP token. Do not use elapsed time as evidence that requests have finished.
3. Confirm the replacement issuer identity has only the intended AAP permissions and can revoke a non-production token created under the current identity, where the AAP authorization model permits that test.
4. Recursively inventory existing Vault leases for the mount using the approved Vault operator procedure. Do not paste credential-read output into that inventory.
5. Revoke or let every inventoried lease expire, then verify the inventory is empty. Recheck the recursive inventory before continuing.
6. Only after the recheck is empty, update the gateway, issuer, TLS settings, custom CA, or configuration through the approved secret-input procedure described in [Configuration](configuration.md). Do not force-revoke leases, bypass revocation, disable the mount, or remove the old authority while it is needed to clean up existing tokens.
7. Issue one controlled credential and revoke its Vault lease. Confirm the upstream token is removed.
8. Resume normal credential reads only after the controlled revoke succeeds.

Do not remove the old issuer identity until the drain and controlled revoke complete.

## Role deletion

Deleting a role stops new reads but does not stop revocation of leases it already issued. Drain or revoke those leases before deleting a role so operators can account for outstanding tokens.

## Incident response

For a suspected issuer-token disclosure, stop granting new workload access, rotate the issuer through the runbook above, and inspect both Vault audit records and AAP token activity. Do not place token values in incident notes or logs.

An upstream issue request with an unknown outcome can create an orphaned token because the plugin does not retry `POST`. Investigate AAP records using the role's description prefix and time window. A retry by the client is a new issuance attempt, not proof that the first request failed.
