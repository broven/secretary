#!/bin/sh
# Installer for the secretary CLI (the client half).
#
#   curl -fsSL https://raw.githubusercontent.com/broven/secretary/main/install.sh | sh
#
# Downloads the prebuilt binary for this platform from a GitHub Release,
# verifies its checksum, and puts `approved-secret` on your PATH. No bun,
# no compiler, no git.
#
# Then offers to install the agent-facing skill via `npx skills add`, which
# asks which agents and which scope. Skip it with SECRETARY_SKIP_SKILL=1 and
# run `npx skills add broven/secretary` yourself whenever you like.
#
# Environment overrides:
#   SECRETARY_VERSION   release tag to install (default: latest)
#   SECRETARY_DIR       where the binary and wrapper live
#   SECRETARY_BIN_DIR   directory to link `approved-secret` into
#   SECRETARY_SKIP_SKILL=1   install only the CLI
set -eu

REPO=${SECRETARY_REPO:-broven/secretary}
install_dir=${SECRETARY_DIR:-"$HOME/.local/share/secretary"}
bin_dir=${SECRETARY_BIN_DIR:-"$HOME/.local/bin"}

die() { echo "error: $*" >&2; exit 1; }

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported OS: $(uname -s) — secretary ships macOS and Linux builds" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64)  arch=x64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
asset="secretary-$os-$arch.tar.gz"

version=${SECRETARY_VERSION:-}
if [ -z "$version" ]; then
  echo "resolving latest release of $REPO …"
  version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$version" ] || die "could not resolve the latest release — pass SECRETARY_VERSION=<tag>"
fi
base="https://github.com/$REPO/releases/download/$version"

work=$(mktemp -d) || die "cannot create a temporary directory"
trap 'rm -rf "$work"' EXIT INT TERM

echo "downloading $asset ($version) …"
curl -fsSL "$base/$asset" -o "$work/$asset" || die "download failed — does $version ship $asset?"

# Checksums are published with the release; a silently corrupted or swapped
# binary is exactly the thing this tool must not be.
if curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS" 2>/dev/null; then
  expected=$(grep " $asset\$" "$work/SHA256SUMS" | awk '{print $1}' | head -1)
  [ -n "$expected" ] || die "SHA256SUMS has no entry for $asset"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$work/$asset" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$work/$asset" | awk '{print $1}')
  else
    die "need sha256sum or shasum to verify the download"
  fi
  [ "$expected" = "$actual" ] || die "checksum mismatch for $asset — refusing to install"
  echo "checksum ok"
else
  die "no SHA256SUMS published for $version — refusing to install unverified"
fi

tar -xzf "$work/$asset" -C "$work" || die "could not unpack $asset"
[ -f "$work/secretary-core" ] || die "archive is missing secretary-core"
[ -f "$work/approved-secret" ] || die "archive is missing the entrypoint wrapper"

mkdir -p "$install_dir/bin" "$install_dir/scripts" "$bin_dir"
install -m 755 "$work/secretary-core" "$install_dir/bin/secretary-core"
# The wrapper locates the binary relative to its own directory, which breaks
# once it is reached through a symlink on PATH ($0 is then the symlink). Bake
# the absolute path in at install time.
sed 's|"$script_dir/../bin/secretary-core"|"'"$install_dir"'/bin/secretary-core"|' \
  "$work/approved-secret" > "$install_dir/scripts/approved-secret"
chmod 755 "$install_dir/scripts/approved-secret"
ln -sf "$install_dir/scripts/approved-secret" "$bin_dir/approved-secret"

echo "installed: $("$install_dir/bin/secretary-core" --version) -> $bin_dir/approved-secret"

case ":${PATH}:" in
  *":$bin_dir:"*) ;;
  *) echo; echo "NOTE: $bin_dir is not on your PATH — add it, e.g.:"; echo "  export PATH=\"$bin_dir:\$PATH\"" ;;
esac

# --- the skill -------------------------------------------------------------
#
# Piped into `sh`, this script's stdin IS the pipe carrying its own text, so a
# prompt here would read the script instead of the user. Hand the child a real
# terminal; where there is none (CI, a background run), print the command
# rather than guessing on the user's behalf.
skill_cmd="npx skills add $REPO"

if [ "${SECRETARY_SKIP_SKILL:-}" = "1" ]; then
  echo
  echo "skipped the skill. Install it whenever you like:  $skill_cmd"
elif ! command -v npx >/dev/null 2>&1; then
  echo
  echo "npx not found, so the agent skill was not installed."
  echo "Install Node.js, then run:  $skill_cmd"
# `[ -r /dev/tty ]` only checks permission bits; with no controlling terminal
# the file is there but opening it fails. Actually open it.
elif { : </dev/tty; } 2>/dev/null; then
  echo
  echo "Installing the agent skill — it will ask which agents and which scope."
  # shellcheck disable=SC2086
  npx --yes skills add "$REPO" </dev/tty >/dev/tty 2>&1 \
    || { echo; echo "the skill step failed; you can retry it any time:  $skill_cmd"; }
else
  echo
  echo "No terminal available for the interactive skill installer. Run:"
  echo "  $skill_cmd"
fi

cat <<'NEXT'

Last step, and it is yours alone — a token must never be pasted into an agent's
conversation:

  approved-secret auth set-url https://your-broker.example
  approved-secret auth set-client-id <client_id>
  approved-secret auth import

Then check it works:

  approved-secret list
NEXT
