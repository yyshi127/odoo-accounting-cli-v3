# Target host capacity remediation evidence, 2026-07-28

This note records the read-only capacity diagnosis for target host
`43.165.173.80` after release `0.1.0.dev224-f8fedaa69548` was routed through
`/opt/odoo-accounting-cli-v3/current`.

No files were deleted, no PostgreSQL data was changed, and no Odoo write was
executed while collecting this evidence.

## Current gate result

`evidence goal-readiness` still fails closed because the target filesystem does
not meet the sandbox-write capacity floor:

- Required ordinary available space: `8589934592` bytes.
- Observed ordinary available space: `2601320448` bytes.
- Shortfall: `5988614144` bytes.
- Filesystem: `/dev/vda2`, mounted at `/`, approximately `79G` total and `97%`
  used.

The full goal-readiness blocker set observed on this release is:

- `Pi scenario acceptance report was not supplied`
- `sandbox database was not observed in the PostgreSQL catalog`
- `sandbox onboarding readiness receipt was not supplied`
- `sandbox provision authorization file was not supplied`
- `sandbox write capacity gate is not ready`
- `sandbox write pipeline readiness report was not supplied`

## V3-owned cleanup plan

The release-bound read-only command:

```bash
bin/odoo-accounting-cli-v3 evidence target-capacity-plan \
  --root / \
  --required-free-bytes 8589934592 \
  --keep-release 0.1.0.dev224-f8fedaa69548 \
  --max-candidates 20 \
  --expected-release 0.1.0.dev224-f8fedaa69548 \
  --expected-commit f8fedaa69548d2ea703bb832375a129e352994a7 \
  --expected-manifest-sha256 ba2c380e0694d01927fc812b5abd8d79a4912107f3c96a59ed021d7a946acf5f \
  --expected-package-sha256 e0ac0572aad189cf815b6beec7ad245a71002fd53b6853442b0d17c9c234cc5f \
  --expected-registry-digest 07e40781c647fa1434b6dca088fca491e17d3cc6319994b97be754a55aea29a2
```

reported `candidate_count:209` and `candidate_reclaimable_bytes:3894293425`.
That means reviewable V3-owned cleanup candidates cannot cover the current
capacity shortfall. Cleanup still requires explicit authorization before any
file removal, but cleanup alone is not enough unless the required floor is
lowered or additional non-V3 data is removed after separate review.

Largest reviewable V3-owned candidates included private evidence fragments under
`/var/lib/odoo-accounting-cli-v3/evidence-private/` and old dependency images
under `/opt/odoo-accounting-cli-v3/dependency-images/`. The current release
`0.1.0.dev224-f8fedaa69548` was protected by `--keep-release` and was not a
cleanup candidate.

## Larger non-V3 directories found by read-only `du`

The largest top-level consumers were:

- `/root`: approximately `27G`
- `/var`: approximately `18G`
- `/mnt`: approximately `16G`
- `/usr`: approximately `6.1G`
- `/opt`: approximately `3.8G`

More detailed read-only inspection found:

- `/root/project`: approximately `15G`
  - `/root/project/ftax_base`: approximately `5.0G`
  - `/root/project/zhaopin`: approximately `2.6G`
  - `/root/project/obsidian`: approximately `2.0G`
  - `/root/project/odoo`: approximately `1.7G`
  - `/root/project/backups`: approximately `1.6G`
- `/root/.hermes`: approximately `8.8G`
  - `/root/.hermes/hermes-agent`: approximately `3.9G`
  - `/root/.hermes/state-snapshots`: approximately `1.7G`
  - `/root/.hermes/sessions`: approximately `1.2G`
  - `/root/.hermes/state.db`: approximately `1.6G`
- `/mnt/odoo`: approximately `16G`
- `/var/lib/postgresql`: approximately `12G`
- `/var/lib/odoo-accounting-cli-v3`: approximately `3.5G`

These locations are not safe to clean automatically. They may contain live Odoo
data, PostgreSQL data, user project work, backups, or agent state.

## Required operator decision before sandbox writes

Before V3 can proceed to real sandbox write drills, one of these must happen:

1. Expand or attach storage so `/` has at least `8589934592` ordinary available
   bytes after reserved blocks.
2. Authorize a reviewed cleanup that includes enough non-current V3 evidence and
   non-V3 data to exceed the capacity floor.
3. Move the sandbox evidence root and related runtime state to a filesystem with
   enough verified capacity, then rerun the release-bound capacity gate against
   that path.

After remediation, rerun:

```bash
bin/odoo-accounting-cli-v3 evidence target-capacity-recheck \
  --path / \
  --required-free-bytes 8589934592
```

Do not start sandbox write drills until the recheck reports
`sandbox_write_capacity_ready:true`.

If the operator chooses to remove any V3-owned cleanup candidates from the
retained `target-capacity-plan` output, first bind that decision to a saved
authorization record with:

```bash
bin/odoo-accounting-cli-v3 evidence target-capacity-cleanup-authorization-template \
  --capacity-plan-file <TARGET_CAPACITY_PLAN_JSON> \
  --candidate-path <SELECTED_V3_OWNED_CANDIDATE_PATH> \
  --operator-id <OPERATOR_ID> \
  --retention-until <UTC_TIMESTAMP>

bin/odoo-accounting-cli-v3 evidence target-capacity-cleanup-authorization-check \
  --authorization-file <TARGET_CAPACITY_CLEANUP_AUTHORIZATION_JSON> \
  --capacity-plan-file <TARGET_CAPACITY_PLAN_JSON> \
  --expected-candidate-path <SELECTED_V3_OWNED_CANDIDATE_PATH>
```

These commands do not delete anything. They only create and validate a
release-plan-bound authorization record so a later cleanup can be audited back
to the exact candidate paths and reclaimable bytes the operator approved.
