#!/bin/sh
# Install the agent-facing skill: SKILL.md (the contract), the entrypoint
# wrapper, and the compiled CLI.
#
# The contract lives in this repo next to the CLI that implements it. The last
# time they lived apart, the CLI was rewritten and the doc kept describing the
# retired system for months.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
dest=${1:-"$HOME/.agents/skills/use-approved-secrets"}

sh "$repo_root/cli/build.sh"

mkdir -p "$dest/bin" "$dest/scripts"

# Back up a SKILL.md we did not write, so an install never destroys local edits.
if [ -f "$dest/SKILL.md" ] && ! cmp -s "$repo_root/skills/use-approved-secrets/SKILL.md" "$dest/SKILL.md"; then
  cp "$dest/SKILL.md" "$dest/SKILL.md.bak"
  echo "backed up previous SKILL.md -> $dest/SKILL.md.bak"
fi

cp "$repo_root/skills/use-approved-secrets/SKILL.md" "$dest/SKILL.md"
cp "$repo_root/cli/bin/secretary-core" "$dest/bin/secretary-core"
# The wrapper resolves the binary relative to its own directory, which breaks
# as soon as the entrypoint is reached through a symlink on PATH ($0 is then
# the symlink, not the real file). Bake the absolute path in at install time.
# The search pattern is single-quoted so the shell does not expand it here.
sed 's|"$script_dir/../bin/secretary-core"|"'"$dest"'/bin/secretary-core"|' \
  "$repo_root/cli/scripts/secretary" > "$dest/scripts/approved-secret"
chmod 755 "$dest/bin/secretary-core" "$dest/scripts/approved-secret"

echo "installed: $dest"
echo "make sure 'approved-secret' on PATH points at $dest/scripts/approved-secret"
