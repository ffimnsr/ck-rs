#!/bin/sh
# Manual smoke test for the compiled `ck` binary.
#
# Runs a happy-path repository lifecycle against a throwaway directory with a
# hermetic Git environment, so the host Git config cannot affect commits.
# Set CK_BIN to smoke-test a different binary (for example a release build).

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin=${CK_BIN:-$root/target/debug/ck}

if [ ! -x "$bin" ]; then
    echo "smoke: $bin not found; run 'make build' first" >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ck-smoke.XXXXXX")
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

home=$work/home
repo=$work/repo
mkdir -p "$home" "$repo"

# Hermetic Git identity: never inherit the operator's config or signing setup.
cat >"$home/.gitconfig" <<'EOF'
[user]
	name = Chainkeeper Smoke
	email = smoke@example.test
[commit]
	gpgsign = false
EOF

HOME=$home
XDG_CONFIG_HOME=$home/.config
GIT_CONFIG_NOSYSTEM=1
export HOME XDG_CONFIG_HOME GIT_CONFIG_NOSYSTEM
unset GIT_CONFIG_GLOBAL CHAINKEEPER_KEY_PASSPHRASE

step() {
    printf '\n== %s\n' "$*"
}

ck() {
    "$bin" --repo "$repo" "$@"
}

fail() {
    echo "smoke: $*" >&2
    exit 1
}

step "version"
"$bin" --version

step "init"
ck init --tenant-id smoke --yes

step "root create"
ck root create --cn "Chainkeeper Smoke Root" --yes

step "intermediate create"
ck intermediate create --name tls --yes

step "issue (json)"
issue_json=$(ck issue \
    --profile tls-server \
    --cn api.smoke.test \
    --dns api.smoke.test \
    --json \
    --yes)
printf '%s\n' "$issue_json" | grep -q '"cert_path"' || fail "issue json missing cert_path"
serial=$(printf '%s\n' "$issue_json" |
    grep -o '"serial": *"[^"]*"' |
    head -n 1 |
    sed 's/.*"\([^"]*\)"$/\1/')
[ -n "$serial" ] || fail "issue json missing serial"
echo "serial: $serial"

step "inspect"
ck inspect --serial "$serial" --json | grep -q '"status"' || fail "inspect json missing status"

step "search"
ck search --query api.smoke.test --json | grep -q '"total"' || fail "search json missing total"

step "tree"
ck tree

step "issue (human output never leaks key material)"
human=$(ck issue --profile tls-server --cn human.smoke.test --dns human.smoke.test --yes)
if printf '%s\n' "$human" | grep -q 'PRIVATE KEY'; then
    fail "human output leaked key material"
fi

step "revoke"
ck revoke --serial "$serial" --reason keyCompromise --yes

step "search revoked"
ck search --status revoked --json | grep -q "$serial" || fail "revoked serial not searchable"

step "index rebuild"
ck index rebuild --repair

step "publish (no commit)"
ck publish --no-commit
[ -f "$repo/publish/manifest.json" ] || fail "publish did not write manifest.json"

step "audit"
ck audit --json | grep -q '"action"' || fail "audit emitted no events"

step "doctor"
# A fresh repository has no generated CRLs, so doctor reports them as errors
# and exits 3. Any other status is a smoke failure.
if ck doctor --json >"$work/doctor.json"; then
    echo "doctor: clean"
else
    status=$?
    [ "$status" -eq 3 ] || fail "doctor exited $status"
    grep -q '"findings"' "$work/doctor.json" || fail "doctor json missing findings"
    echo "doctor: expected CRL findings (exit 3)"
fi

printf '\nsmoke: ok (%s)\n' "$bin"
