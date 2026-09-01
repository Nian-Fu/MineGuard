#!/bin/sh
set -eu

case "$0" in
  */*) script_path=${0%/*} ;;
  *) script_path=. ;;
esac
script_dir=$(CDPATH= cd -- "$script_path" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

for command_name in find git grep mktemp rmdir wc; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "source text verification requires $command_name" >&2
    exit 2
  fi
done

failed=0
empty_dir=$(mktemp -d "${TMPDIR:-/tmp}/mineguard-source-text.XXXXXX")
trap 'rmdir "$empty_dir"' EXIT HUP INT TERM

check_path() {
  source_path=$1
  if [ -d "$source_path" ]; then
    comparison_source=$empty_dir
  else
    comparison_source=/dev/null
  fi
  output=$(git diff --no-index --check "$comparison_source" "$source_path" 2>&1 || true)
  errors=$(
    printf '%s\n' "$output" \
      | grep -v '^warning: in the working copy' \
      || true
  )
  if [ -n "$errors" ]; then
    printf '%s\n' "$errors" >&2
    failed=1
  fi
}

checked=0
for relative_path in .github backend deploy docs frontend research tests \
  .env.example .gitignore docker-compose.yml README.md; do
  source_path="$repository_root/$relative_path"
  [ -e "$source_path" ] || continue
  check_path "$source_path"
  if [ -d "$source_path" ]; then
    path_count=$(find "$source_path" -type f -print | wc -l)
  else
    path_count=1
  fi
  checked=$((checked + path_count))
done

for marker_character in '<' '=' '>'; do
  marker="$marker_character$marker_character$marker_character$marker_character"
  marker="$marker$marker_character$marker_character$marker_character"
  if grep -R -n -F "$marker" "$repository_root" \
    --exclude-dir=.git >/dev/null 2>&1; then
    echo "source text verification found merge marker: $marker" >&2
    failed=1
  fi
done

if ! find "$repository_root" -type f -name '*.sh' -exec sh -n {} +; then
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "source_text_verification=passed checked_files=$checked"
