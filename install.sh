#!/bin/sh
# One-shot installer for the secretary CLI and its agent-facing skill.
#
#   curl -fsSL https://raw.githubusercontent.com/broven/secretary/main/install.sh | sh
#
# or, from a checkout:   sh install.sh
#
# Installs:
#   <skill dir>/SKILL.md              the agent-facing contract
#   <skill dir>/bin/secretary-core    the compiled CLI
#   <skill dir>/scripts/approved-secret   entrypoint wrapper (env-scrubbing)
#   <bin dir>/approved-secret         symlink onto PATH
#
# Override with SECRETARY_SKILL_DIR / SECRETARY_BIN_DIR.
set -eu

REPO=${SECRETARY_REPO:-broven/secretary}
REF=${SECRETARY_REF:-main}
skill_dir=${SECRETARY_SKILL_DIR:-"$HOME/.agents/skills/use-approved-secrets"}
bin_dir=${SECRETARY_BIN_DIR:-"$HOME/.local/bin"}

die() { echo "error: $*" >&2; exit 1; }

# The CLI is a compiled Bun binary; there is no prebuilt artifact to fall back on.
command -v bun >/dev/null 2>&1 || die "bun is required to build the CLI — install it from https://bun.sh then re-run"

# Prefer the checkout this script sits in; otherwise fetch a tarball (no git needed).
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P) || script_dir=""
if [ -n "$script_dir" ] && [ -f "$script_dir/cli/build.sh" ] && [ -d "$script_dir/skills/use-approved-secrets" ]; then
  src=$script_dir
  cleanup() { :; }
else
  command -v curl >/dev/null 2>&1 || die "curl is required to download the source"
  command -v tar >/dev/null 2>&1 || die "tar is required to unpack the source"
  work=$(mktemp -d) || die "cannot create a temporary directory"
  cleanup() { rm -rf "$work"; }
  trap cleanup EXIT INT TERM
  echo "fetching $REPO@$REF …"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF" \
    | tar -xzf - -C "$work" || die "download failed — is the repository public and is '$REF' a branch?"
  src=$(find "$work" -maxdepth 1 -mindepth 1 -type d | head -1)
  [ -n "$src" ] || die "unexpected archive layout"
fi

[ -f "$src/skills/use-approved-secrets/install.sh" ] || die "source tree is missing the skill installer"
SECRETARY_SKILL_DEST="$skill_dir" sh "$src/skills/use-approved-secrets/install.sh" "$skill_dir"

# Put the entrypoint on PATH. A symlink (not a copy) so the next install is picked
# up without touching this directory again.
mkdir -p "$bin_dir"
ln -sf "$skill_dir/scripts/approved-secret" "$bin_dir/approved-secret"
echo "linked: $bin_dir/approved-secret"

case ":${PATH}:" in
  *":$bin_dir:"*) ;;
  *) echo; echo "NOTE: $bin_dir is not on your PATH — add it, e.g.:"; echo "  export PATH=\"$bin_dir:\$PATH\"" ;;
esac

cat <<'NEXT'

Done. Two bootstrap steps remain, and both are yours to run — a token must never
be pasted into an agent's conversation:

  approved-secret auth set-url https://your-broker.example
  approved-secret auth import        # paste the token issued by `secretary client add`

Then check it works:

  approved-secret list
NEXT
