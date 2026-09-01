#!/bin/sh
set -eu

case "$0" in
  */*) script_path=${0%/*} ;;
  *) script_path=. ;;
esac
script_dir=$(CDPATH= cd -- "$script_path" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
failed=0
newline_ifs='
'

for command_name in awk grep; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "release input rejected: required command is missing: $command_name" >&2
    exit 2
  fi
done

fail() {
  echo "release input rejected: $1" >&2
  failed=1
}

logical_instructions() {
  awk '
    {
      sub(/\r$/, "")
      if ($0 ~ /^[[:space:]]*#/) next
      continued = ($0 ~ /\\[[:space:]]*$/)
      sub(/\\[[:space:]]*$/, "")
      record = record " " $0
      if (!continued) {
        print record
        record = ""
      }
    }
    END { if (record != "") print record }
  ' "$1"
}

python_locks="
backend/requirements-api.lock
backend/requirements-edge.lock
backend/requirements-dev.lock
research/rl_scheduler/requirements.lock
"
for relative_path in $python_locks; do
  lock_file="$repository_root/$relative_path"
  if [ ! -s "$lock_file" ]; then
    fail "missing non-empty hash lock $relative_path"
    continue
  fi
  if ! grep -Eq -- '--hash=sha256:[0-9a-f]{64}' "$lock_file"; then
    fail "$relative_path contains no SHA-256 package hashes"
  fi
  if ! awk '
    function check_record() {
      if (record == "") return
      if (record ~ /^[[:space:]]*--/) {
        if (record !~ /^[[:space:]]*--only-binary[=:][[:space:]]*:all:[[:space:]]*$/) {
          bad = 1
        }
      } else {
        exact = record ~ /^[[:space:]]*[A-Za-z0-9_.-]+(\[[A-Za-z0-9_.,-]+\])?==[^[:space:]\\]+/
        hashed = record ~ /(^|[[:space:]])--hash=sha256:[0-9a-f]{64}([[:space:]]|$)/
        if (!exact || !hashed) bad = 1
      }
      record = ""
    }
    {
      sub(/\r$/, "")
      if ($0 ~ /^[[:space:]]*(#|$)/) next
      continued = ($0 ~ /\\[[:space:]]*$/)
      sub(/\\[[:space:]]*$/, "")
      record = record " " $0
      if (!continued) check_record()
    }
    END {
      check_record()
      exit bad
    }
  ' "$lock_file"; then
    fail "$relative_path must exact-pin and hash every requirement; only --only-binary=:all: is allowed as a standalone option"
  fi
  if grep -Eiq -- '(^|[[:space:]])(-e|--editable|git\+|https?://)' "$lock_file"; then
    fail "$relative_path contains an editable, VCS, or direct URL dependency"
  fi
  if grep -Eiq -- '(^|[[:space:]])(--index-url|--trusted-host|--extra-index-url|--find-links|--requirement|--constraint)([=[:space:]]|$)' "$lock_file"; then
    fail "$relative_path contains an unapproved package source or nested-input option"
  fi
done

npm_lock="$repository_root/frontend/package-lock.json"
if [ ! -s "$npm_lock" ]; then
  fail "missing frontend/package-lock.json"
elif ! grep -Eq '"lockfileVersion"[[:space:]]*:[[:space:]]*3([,[:space:]]|$)' "$npm_lock"; then
  fail "frontend/package-lock.json must use lockfileVersion 3"
fi

backend_instructions=
[ ! -s "$repository_root/backend/Dockerfile" ] \
  || backend_instructions=$(logical_instructions "$repository_root/backend/Dockerfile")
if ! printf '%s\n' "$backend_instructions" | awk '
  /pip[[:space:]]+install/ && /--require-hashes/ && /requirements-api\.lock/ { found = 1 }
  END { exit !found }
'; then
  fail "backend/Dockerfile does not install requirements-api.lock with --require-hashes"
fi
edge_instructions=
[ ! -s "$repository_root/backend/Dockerfile.edge" ] \
  || edge_instructions=$(logical_instructions "$repository_root/backend/Dockerfile.edge")
if ! printf '%s\n' "$edge_instructions" | awk '
  /pip[[:space:]]+install/ && /--require-hashes/ && /requirements-edge\.lock/ { found = 1 }
  END { exit !found }
'; then
  fail "backend/Dockerfile.edge does not install requirements-edge.lock with --require-hashes"
fi
frontend_instructions=
[ ! -s "$repository_root/frontend/Dockerfile" ] \
  || frontend_instructions=$(logical_instructions "$repository_root/frontend/Dockerfile")
if ! printf '%s\n' "$frontend_instructions" | awk '
  /npm[[:space:]]+ci([[:space:]]|$)/ { npm_ci = 1 }
  /package-lock\.json/ { lock_copy = 1 }
  END { exit !(npm_ci && lock_copy) }
'; then
  fail "frontend/Dockerfile does not build from package-lock.json with npm ci"
fi
research_instructions=
[ ! -s "$repository_root/research/rl_scheduler/Dockerfile" ] \
  || research_instructions=$(logical_instructions "$repository_root/research/rl_scheduler/Dockerfile")
if ! printf '%s\n' "$research_instructions" | awk '
  /pip[[:space:]]+install/ && /--require-hashes/ && /requirements\.lock/ { found = 1 }
  END { exit !found }
'; then
  fail "research/rl_scheduler/Dockerfile does not install requirements.lock with --require-hashes"
fi

ci_instructions=
[ ! -s "$repository_root/.github/workflows/ci.yml" ] \
  || ci_instructions=$(logical_instructions "$repository_root/.github/workflows/ci.yml")
if ! printf '%s\n' "$ci_instructions" | awk '
  /pip[[:space:]]+install/ && /--require-hashes/ && /requirements-dev\.lock/ { dev = 1 }
  /pip[[:space:]]+install/ && /--require-hashes/ && /requirements\.lock/ { rl = 1 }
  /npm[[:space:]]+ci([[:space:]]|$)/ { npm_ci = 1 }
  END { exit !(dev && rl && npm_ci) }
'; then
  fail ".github/workflows/ci.yml must consume dev/RL hash locks and the npm lock"
fi

for dockerfile in "$repository_root"/backend/Dockerfile \
  "$repository_root"/backend/Dockerfile.edge \
  "$repository_root"/frontend/Dockerfile \
  "$repository_root"/research/rl_scheduler/Dockerfile; do
  if [ ! -s "$dockerfile" ]; then
    fail "missing non-empty ${dockerfile#"$repository_root/"}"
    continue
  fi
  from_lines=$(grep -E '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" || true)
  if [ -z "$from_lines" ]; then
    fail "${dockerfile#"$repository_root/"} contains no FROM instruction"
    continue
  fi
  previous_ifs=$IFS
  IFS=$newline_ifs
  for from_line in $from_lines; do
    if ! printf '%s\n' "$from_line" \
      | grep -Eq '@sha256:[0-9a-f]{64}([[:space:]]|$)'; then
      fail "${dockerfile#"$repository_root/"} has an unpinned FROM: $from_line"
    fi
  done
  IFS=$previous_ifs
done

for compose_file in "$repository_root/docker-compose.yml" \
  "$repository_root/deploy/docker-compose.edge.yml"; do
  if [ ! -s "$compose_file" ]; then
    fail "missing non-empty ${compose_file#"$repository_root/"}"
    continue
  fi
  image_lines=$(grep -E '^[[:space:]]*image:[[:space:]]+' "$compose_file" || true)
  previous_ifs=$IFS
  IFS=$newline_ifs
  for image_line in $image_lines; do
    if ! printf '%s\n' "$image_line" \
      | grep -Eq '@sha256:[0-9a-f]{64}([[:space:]]|$)'; then
      fail "${compose_file#"$repository_root/"} has an unpinned image: $image_line"
    fi
  done
  IFS=$previous_ifs
done

for workflow in "$repository_root"/.github/workflows/*.yml \
  "$repository_root"/.github/workflows/*.yaml; do
  [ -f "$workflow" ] || continue
  action_lines=$(
    grep -E '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]+' "$workflow" \
      || true
  )
  previous_ifs=$IFS
  IFS=$newline_ifs
  for action_line in $action_lines; do
    if printf '%s\n' "$action_line" \
      | grep -Eq 'uses:[[:space:]]+\./'; then
      continue
    fi
    if ! printf '%s\n' "$action_line" | grep -Eq '@[0-9a-f]{40}([[:space:]#]|$)'; then
      fail "${workflow#"$repository_root/"} has an action not pinned by commit: $action_line"
    fi
  done
  IFS=$previous_ifs
done

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "supply_chain_release_inputs=passed"
