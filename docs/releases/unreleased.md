Notes for the next seihai-listserver release. One line per user-visible change, added by the PR that makes it; the release PR moves them into `vX.Y.Z.md` (VERSIONING.md).

- Add real-file SQLite acceptance tests for supported-layout reopen, persistent import-once records, and preserving populated data when a newer schema is refused.

- Refuse new machine-ID allocation when the table's supported ID range is exhausted, before writing an unreadable row or changing live state. Existing IDs can still match and gain keys.

- Built on seihai-core v0.7.2 (was v0.6.3): NewWorld beta 1/2 as real versions (with their 8-byte COLORS, which v0.7.0 had as 7), the version-token/profile audit, GS2 reading non-numeric text as -1, and the PLO_FILE mod time for 2.05 and the NewWorld betas (v0.7.2).

- Reconcile the active roadmaps with merged machine-ID exhaustion and SQLite preservation acceptance, keeping migration/lab/release limits explicit.
