#!/usr/bin/env bash
set -Eeuo pipefail

readonly EXIT_USAGE=64
readonly EXIT_ISOLATION=70
readonly INSIDE_TOKEN=__odoo_v3_private_mount_gate_inside__

fail_isolation() {
  printf 'target Linux mount-isolation gate rejected the host state\n' >&2
  exit "$EXIT_ISOLATION"
}

var_lib_mountinfo() {
  awk '$5 == "/var/lib" { print }' /proc/self/mountinfo
}

assert_not_suspicious() {
  local snapshot=$1
  if grep -Eiq '(^|[[:space:]])[^[:space:]]*/(tmp|var/tmp)/|(^|/)(odoo-v3|fake-var-lib)(/|[[:space:]]|$)|deleted' <<<"$snapshot"; then
    fail_isolation
  fi
}

inside_private_namespace() {
  local self_namespace init_namespace propagation
  self_namespace="$(readlink /proc/self/ns/mnt)"
  init_namespace="$(readlink /proc/1/ns/mnt)"
  test -n "$self_namespace"
  test -n "$init_namespace"
  test "$self_namespace" != "$init_namespace" || fail_isolation

  propagation="$(findmnt -n -o PROPAGATION /)"
  case "$propagation" in
    private|unbindable) ;;
    *) fail_isolation ;;
  esac

  if awk '$5 == "/" {
      for (field = 7; field <= NF && $field != "-"; field++) {
        if ($field ~ /^(shared|master):/) exit 1
      }
      found = 1
    }
    END { if (!found) exit 1 }
  ' /proc/self/mountinfo; then
    :
  else
    fail_isolation
  fi

  test "$#" -gt 0 || exit "$EXIT_USAGE"
  exec "$@"
}

if [[ ${1-} == "$INSIDE_TOKEN" ]]; then
  shift
  inside_private_namespace "$@"
fi

if [[ $# -eq 0 ]]; then
  printf 'usage: run-private-mount-gate.sh COMMAND [ARG ...]\n' >&2
  exit "$EXIT_USAGE"
fi

for executable in awk findmnt grep readlink unshare; do
  command -v "$executable" >/dev/null 2>&1 || fail_isolation
done

readonly before="$(var_lib_mountinfo)"
assert_not_suspicious "$before"

set +e
unshare \
  --mount \
  --propagation private \
  --fork \
  --kill-child=KILL \
  -- \
  "$0" "$INSIDE_TOKEN" "$@"
readonly command_status=$?
set -e

readonly after="$(var_lib_mountinfo)"
if [[ "$after" != "$before" ]]; then
  fail_isolation
fi
assert_not_suspicious "$after"

exit "$command_status"
