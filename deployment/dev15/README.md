# Dev15 staged read-evidence toolchain

This directory is the reviewed, fixed-byte toolchain for one real Odoo test
database read of `acct.multicurrency.balance_read.v1`. It installs beside the
application release. It does not create or change `current`, systemd units,
Pi Bridge routing, V2 files, or accounting records.

## Fixed contents

The installed directory is exactly
`/opt/odoo-accounting-cli-v3/toolchains/0.1.0.dev15-read-toolchain.1` and
contains ten regular, single-link files:

- `TOOLCHAIN-MANIFEST.json`
- `README.md`
- `check_toolchain.py`
- `install_toolchain.py`
- `runtime_setup.py`
- `sign_read.py`
- `run_multicurrency_read.py`
- `multicurrency_sql_oracle.py`
- `verify_evidence.py`
- `read_plan.json`

Manifest schema 2 has two ordered lists. `files` is exactly
`install_toolchain.py`, `runtime_setup.py`, `sign_read.py`,
`run_multicurrency_read.py`, `multicurrency_sql_oracle.py`,
`verify_evidence.py`, and `read_plan.json`. `control_files` is exactly
`README.md` and `check_toolchain.py`. Every entry contains only `name`,
`sha256`, and `size`.

The manifest cannot authenticate itself. Deployment must obtain its expected
raw SHA-256 from the reviewed, signed annotation of tag
`toolchain/0.1.0.dev15-read-toolchain.1`, never from the upload directory or
from a value stored inside the manifest. The installer requires that external
digest and rejects any byte, file-set, order, identity, ownership, mode,
symlink, or hard-link mismatch. Do not move or reissue this tag.

The only authorized SSH signing key has Git tagger/committer principal
`yyshi127@users.noreply.github.com` and fingerprint
`SHA256:GFGfgQoBqTNZZ47Ts+lDRURoCwpmSv9/o24gzkFQjXs`. From a trusted checkout,
verify the remote annotated tag object, its peeled signed commit, and the
annotation digest before copying any file. `$RELEASE_PUBLIC_KEY` must be an
independently provisioned public key, not a key taken from the tag or upload:

```sh
set -eu
TAG=toolchain/0.1.0.dev15-read-toolchain.1
SIGNING_PRINCIPAL=yyshi127@users.noreply.github.com
SIGNING_FINGERPRINT=SHA256:GFGfgQoBqTNZZ47Ts+lDRURoCwpmSv9/o24gzkFQjXs
RELEASE_PUBLIC_KEY=/root/odoo-accounting-cli-v3-release.pub
ALLOWED_SIGNERS=/root/odoo-accounting-cli-v3-release.allowed-signers

test "$(ssh-keygen -E sha256 -lf "$RELEASE_PUBLIC_KEY" | awk '{print $2}')" = \
  "$SIGNING_FINGERPRINT"
KEY_TYPE_AND_BODY=$(awk 'NR == 1 {print $1 " " $2}' "$RELEASE_PUBLIC_KEY")
(umask 077 && printf '%s namespaces="git" %s\n' \
  "$SIGNING_PRINCIPAL" "$KEY_TYPE_AND_BODY" >"$ALLOWED_SIGNERS")

git fetch --no-tags origin "refs/tags/$TAG:refs/tags/$TAG"
TAG_OBJECT=$(git rev-parse --verify "$TAG^{tag}")
TAG_COMMIT=$(git rev-parse --verify "$TAG^{commit}")
REMOTE_TAG_OBJECT=$(git ls-remote --tags origin "refs/tags/$TAG" | awk 'NR == 1 {print $1}')
REMOTE_TAG_COMMIT=$(git ls-remote --tags origin "refs/tags/$TAG^{}" | awk 'NR == 1 {print $1}')
test -n "$REMOTE_TAG_OBJECT" && test "$TAG_OBJECT" = "$REMOTE_TAG_OBJECT"
test -n "$REMOTE_TAG_COMMIT" && test "$TAG_COMMIT" = "$REMOTE_TAG_COMMIT"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$ALLOWED_SIGNERS" \
  verify-tag "$TAG"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$ALLOWED_SIGNERS" \
  verify-commit "$TAG_COMMIT"

ANNOTATION_DIGESTS=$(git for-each-ref --format='%(contents)' "refs/tags/$TAG" | \
  sed -n 's/^.*TOOLCHAIN-MANIFEST\.json SHA-256: \([0-9a-f]\{64\}\)$/\1/p')
test "$(printf '%s\n' "$ANNOTATION_DIGESTS" | sed '/^$/d' | wc -l)" -eq 1
EXPECTED_MANIFEST_SHA256=$ANNOTATION_DIGESTS
TAG_MANIFEST_SHA256=$(git show \
  "${TAG_COMMIT}:deployment/dev15/TOOLCHAIN-MANIFEST.json" | sha256sum | awk '{print $1}')
test "$TAG_MANIFEST_SHA256" = "$EXPECTED_MANIFEST_SHA256"
export EXPECTED_MANIFEST_SHA256 TAG TAG_COMMIT
```

The application identity is fixed to release
`0.1.0.dev15-c4616386f921`, commit
`c4616386f921946cf43cde2de449d2938a837422`, release-manifest identity SHA-256
`f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2`,
raw installed `RELEASE-MANIFEST.json` SHA-256
`21b220ab3bea012201d3d8d06b3f12c4841c08d5a37afd416889729f47d8e3d6`,
package SHA-256
`71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf`,
and registry digest
`ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b`.
The raw SHA-256 of `read_plan.json` is
`860de4fb5b4efe41f760295b0b8eee4ae8b63f15d70e25e418640c8eb5f04c80`.

## Deployment and execution

Use a new `root:root` `0700` upload directory outside
`/opt/odoo-accounting-cli-v3`. Copy the exact ten files from `$TAG_COMMIT`,
then apply the exact metadata required by the installer. On the server, retain
the independently verified digest from the preceding authorization step:

```sh
set -eu
UPLOAD=/root/odoo-accounting-cli-v3-dev15-read-toolchain.1-upload
TOOLCHAIN=/opt/odoo-accounting-cli-v3/toolchains/0.1.0.dev15-read-toolchain.1
export EXPECTED_MANIFEST_SHA256 UPLOAD TOOLCHAIN
install -d -o root -g root -m 0700 "$UPLOAD"
# Copy exactly the ten fixed files into $UPLOAD before sealing them.
chown root:root "$UPLOAD"/*
chmod 0444 "$UPLOAD"/*
/usr/bin/python3 -I "$UPLOAD/install_toolchain.py" \
  "$UPLOAD" "$EXPECTED_MANIFEST_SHA256"
```

`$EXPECTED_MANIFEST_SHA256` must be exactly 64 lowercase hexadecimal
characters copied from the signed tag annotation. An invocation that does not
supply this external digest is refused.

After installation, run these gates in order:

1. Run the installed checker with the same digest used by the installer:
   `/usr/bin/python3 -I "$TOOLCHAIN/check_toolchain.py"
   "$EXPECTED_MANIFEST_SHA256"`.
2. Run the installed `runtime_setup.py` as root, without `--test-root`, twice;
   the second run must return the existing byte-identical runtime.
3. Re-run `/usr/bin/python3 -I "$TOOLCHAIN/check_toolchain.py"
   "$EXPECTED_MANIFEST_SHA256"` and independently verify that Odoo, Pi
   Bridge, V2, systemd unit state, and routing have not changed.
4. Select a new, safe, direct child of
   `/var/lib/odoo-accounting-cli-v3/evidence`, then run
   `/usr/bin/python3 -I "$TOOLCHAIN/run_multicurrency_read.py"
   "$EVIDENCE_DIR" "$EXPECTED_MANIFEST_SHA256"` as root.
5. Run `/usr/bin/python3 -I "$TOOLCHAIN/verify_evidence.py"
   "$EVIDENCE_DIR" "$EXPECTED_MANIFEST_SHA256"` as root and retain its
   root-owned external anchor under
   `/var/lib/odoo-accounting-cli-v3/evidence-anchors`.

The installer, both checker invocations, runner, and verifier must receive the
same unchanged `$EXPECTED_MANIFEST_SHA256` obtained from the signed tag. Each
command refuses a missing, malformed, or byte-mismatched digest.

The committed plan is bound to test database `odoo_test`, database UUID
`19b09656-d10f-11f0-9065-00163e54a5ad`, PostgreSQL system identifier
`7616327373742442245`, company 9, and user 2. The runner and independent SQL
oracle are read-only with respect to Odoo/PostgreSQL business data. The runner
does write only its dedicated CLI authentication/receipt state, evidence
directory, and external evidence anchor; it is not filesystem read-only. A
missing signed receipt, mismatched SQL oracle,
mismatched database/system/V2/Pi baseline, changed service state, stderr,
timeout, or nonzero exit is failure; it must never be reported as business
success.

State snapshots require each dedicated SQLite directory to contain only its
single `state.sqlite3` file (or be empty before first use). A lingering WAL,
SHM, journal, unexpected sibling, metadata change, or concurrent writer is a
closed-gate failure. The runner uses an immutable read connection and proves
the directory and database fingerprints are unchanged afterward. Likewise,
any directory symlink inside a systemd unit search root is rejected instead
of being followed across the trusted search boundary.

This toolchain contains no credentials. `runtime_setup.py` creates the two
role-separated HMAC secrets and candidate state below the dedicated Dev15
paths with restricted ownership. Do not copy those secrets, mutable state, or
evidence into Git or a release package.

## Recovery and rollback

An install or setup failure must be investigated and rerun from a fresh
root-only upload; do not edit an installed toolchain in place. Because this is
a side-load and no route is changed, rollback means leaving the immutable
candidate unselected and preserving the failed evidence/state for audit. A
new reviewed version is required for any byte change. Never delete V2 or
change production routing as part of this Dev15 read gate.
