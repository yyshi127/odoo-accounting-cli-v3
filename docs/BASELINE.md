# V3 baseline

Baseline date: 2026-07-13 (Asia/Shanghai)

## Evidence status

| Area | Current evidence | Status |
|---|---|---|
| V3 source | No V3 source directory existed before this baseline | Confirmed locally |
| V2 CLI source | Referenced as `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2`; not present in the local workspace | Missing locally |
| Odoo bridge | Three local variants exist; `sudo_ai_bot/models/accounting_cli.py` differs from both remote snapshot copies | Divergent |
| Odoo module version | Local and remote snapshot manifests both report `1.2.0` despite differing accounting bridge content | Version collision |
| Pi Bridge | Only `_remote_pi_agent_bridge` snapshot is present locally | Historical snapshot only |
| Git history | Workspace `master` has no commits and most files are untracked | No source-of-truth baseline |
| Target server | Read-only SSH succeeded as `root`; hostname is `VM-0-6-ubuntu` | Confirmed 2026-07-13 |
| Runtime services | `odoo19.service` and `sudo-pi-agent-bridge.service` reported active | Confirmed 2026-07-13 |
| Server V2 | `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2`, owned by `odoo:odoo`; package metadata says `0.1.0`; no Git metadata | Confirmed, untraceable source |
| Server V3 | `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v3` does not exist | Confirmed absent |
| Pi Bridge V2 copy | A second complete V2 tree exists under `/mnt/odoo/odoo19/custom/services/pi-agent-bridge/odoo_accounting_agent_cli_v2` | Confirmed duplicate |
| V2 copy equality | Active source-tree aggregate hashes differ; `commands/backend.py` also differs while both packages report `0.1.0` | Confirmed version collision |
| Odoo module | Active `sudo_ai_bot` manifest reports `1.2.0`; manifest SHA-256 is `640ddb271cf04067bc5be68de7d7fb8620e9c19a308417295650b3811279d96b` | Confirmed |
| Production writes | No authorization was provided | Prohibited |
| Sandbox database | No dedicated sandbox identity or connection evidence is available | Not verified |

## Local artifact hashes

The following SHA-256 values were observed during the baseline audit:

- `sudo_ai_bot/models/accounting_cli.py`: `10C27ABEAE72F439DBDB867C1684E2962D4DEB8909B35E304FA3C7B02...`
- `_remote_current_sudo_ai_bot/models/accounting_cli.py`: `367C3470A814B85C6F693C8C760A30DCF6C273074456DEA04549FF178...`
- `_remote_sudo_ai_bot/models/accounting_cli.py`: identical to the remote-current snapshot
- `_remote_pi_agent_bridge/server.mjs`: `FAE40056F346DF95E55443A1CA44CFD580577C6A7505B87BB46ABF9F1...`
- `_remote_pi_agent_bridge/extensions/odoo-tools.ts`: `C34484BFB5934513DB85A594049A3360B1AF62F2496C4C951B4CAA000...`

Ellipses reflect truncated console evidence. A server-authoritative inventory and
full hash manifest must be generated after read-only SSH access is restored.

## Server evidence captured

- V2 active-source aggregate: `e25af9e41f1f79d629404d1106f9bb61999b3fe795dcfb8d4236589b5c0bd69d`
- Pi Bridge embedded V2 aggregate: `8c3730499ce554ca2bf0a58c2332d8800b1cb05c4f7188b5ba2a05dc5672428f`
- Tools V2 `commands/backend.py`: `2ce74f56013a85771b05c179b2f95dc80ea2981ee1668114383131cfcc179131`
- Pi Bridge V2 `commands/backend.py`: `b9a6405040f25b518eda82ce5caf3348cac73d4453509939c3a354652813cb78`
- Pi Bridge `server.mjs`: `fae40056f346df95e55443a1ca44cfd580577c6a7505b87bb46abf9f1d60df9f`
- Odoo service runs as `odoo:odoo` using `/opt/odoo/odoo19/odoo-server/odoo-bin`.
- Pi Bridge runs as `odoo:odoo` from `/mnt/odoo/odoo19/custom/services/pi-agent-bridge`.
- Odoo configured add-ons path includes `/mnt/odoo/odoo19/custom/addons`; HTTP port is 8070.
- Odoo databases observed: `codex_sgf_test_20260713_01`, `odoo`, `odoo_2601`, `odoo_sg`, and `odoo_test` (plus PostgreSQL administrative databases).
- `account` version `19.0.1.4` and `account_accountant` version `19.0.1.1` are installed in all five observed Odoo databases.
- `sudo_ai_bot` version `19.0.1.2.0` is installed in `codex_sgf_test_20260713_01`, `odoo_2601`, `odoo_sg`, and `odoo_test`; it is uninstalled in `odoo`.
- `codex_sgf_test_20260713_01` contains companies `YourCompany`, `My US Company`, and `SG Company`. Its sandbox role is not yet proven by configuration or user confirmation, so no write is authorized.

The server V2 directory contains many in-place backup trees and generated
artifacts. These are evidence inputs only and must not be copied wholesale into
V3. Reuse decisions require per-module provenance, focused tests, and review.

## Boundary decision

- Local V3 source root: `odoo-accounting-cli-v3/`
- Proposed server release root: `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v3/releases/<version>/`
- Proposed immutable package name: `odoo-accounting-cli-v3-<version>-<commit>.tar.gz`
- V2 remains unchanged and independently runnable.
- V3 may consume audited V2 logic only through a documented import/port record;
  copied code must retain provenance and tests.

## Phase-one exit gate

The read-only baseline is not complete until server evidence records the running
Odoo module, V2 CLI, Pi Bridge, service definitions, configuration paths, Git or
package metadata, file hashes, database names, company scopes, and sandbox
identity. No production write test is part of this gate.
