# Phase 6 — Rule persistence schema

## Implemented

- Added a typed `Vec<Rule>` to the encrypted `ConfigDocument`.
- Reuses the core rule model, including target kind, action, enabled state, label and stable ID.
- Bounds the collection to 2,048 records.
- Validates every rule with the core validator and rejects duplicate IDs.
- Marks the field with a serde default so existing schema-v1 documents without a `rules` field load as an empty rule list.
- Added storage tests for encrypted rule round-trip, old schema-v1 compatibility, duplicate IDs and invalid rule rejection.

## Not yet connected to the desktop UI

The rule editor still operates on the in-memory `CoreEngine`. The app does not yet load or save `ConfigDocument` records. The current configuration document requires an Argon2id PIN verifier, but the app has no first-run PIN setup/unlock screen or data-directory lifecycle. Creating a configuration without that workflow would require an insecure default credential or a bypass of the existing security boundary; neither is acceptable.

## Next work

1. Implement the first-run PIN setup and unlock workflow, including lockout persistence.
2. Resolve and secure the per-user application data directory.
3. Load the encrypted document at startup and hydrate the core rules.
4. Persist add/edit/enable/disable/delete operations without losing unrelated settings.
5. Surface corrupt-store and unavailable-store errors without silently overwriting existing data.

## Validation

Source changes and tests are committed, but no Rust compiler, Cargo test run, formatting check, Clippy run or Windows runtime test was available in this environment. Do not treat the tests as executed or passing.
