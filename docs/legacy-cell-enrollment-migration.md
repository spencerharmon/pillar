# Legacy cell conversion for enrollment

Cells created before independent cell credentials existed keep a `streamdb/`
whose cell ID and group-key seed are derived from the device's private
`identity.key` bytes. `pillar node run` still serves such a cell, but node
enrollment refuses to distribute those credentials (approval answers
`DENIED legacy-cell-credentials` and records no admission). Converting the
cell re-seals its existing journal under fresh, independent credentials so the
SAME logical cell can admit other nodes through the normal signed enrollment
flow (`docs/bootstrap-node-enrollment.md`).

## What is preserved

- Device identity and its segment signer (unchanged; never copied to joiners).
- Every journal op payload, in order: op IDs and the Merkle root are
  identical before and after (the tool verifies this from disk).
- Users, custody, membership, administrator login, admitted signers and all
  resources (they are journal state).
- The legacy `streamdb/` directory is never modified or deleted.

## Contract changes (acknowledged explicitly)

- The cryptographic cell ID changes. Client configs exported before the
  conversion carry the legacy cell material and are rejected afterwards.
  Already admitted signer keys remain admitted: log in and re-export, or replace
  only `cell_id_hex`/`cell_seed_hex` in an existing config with the new export's.
- Old ciphertext is not discarded: the legacy stream stays readable by the
  legacy binary path and is the rollback source.

## Procedure (node stopped; nothing is automatic)

1. Back up the data directory.
2. `pillar node migrate-legacy-cell --data-dir DIR --plan` — read-only; prints
   op count, Merkle root, and the contract above.
3. `pillar node migrate-legacy-cell --data-dir DIR --apply --acknowledge-cell-id-change`
   - writes the `legacy-cell-migration.json` marker (state `staged`) and staged
     credentials, re-seals into `legacy-cell-migration.staging/streamdb`,
     verifies the reopened stream reproduces the legacy ops and root exactly,
     renames it to `streamdb-converted/`, installs `cell-credentials.json`, then
     flips the marker to `committed` (the commit point).
   - Interrupted at any step: `node run` refuses to start; rerun the same
     `--apply` (idempotent resume) or `--rollback`.
4. Start the node; re-export client configs; approve joiners as usual.

## Rollback

`pillar node migrate-legacy-cell --data-dir DIR --rollback` parks (never
deletes) the converted stream, staging data, credentials and marker under
`legacy-cell-migration.rolled-back-<nonce>/`; the node then boots the legacy cell.
After commit it is allowed only before the boundary: no op written to the
converted stream and no enrollment approved with the new credentials. Past that
it is refused ("rollback boundary passed").

## Refusals

Corrupt or foreign legacy stream, a different `identity.key` than the one that
wrote the stream or started the migration, a corrupt marker, a running node
(lock held), an enrolled node, or pre-existing `cell-credentials.json` without a
marker — all refuse before writing anything.

Verification: `cargo test -p pillar-cli --test legacy_cell_enrollment_migration`.
