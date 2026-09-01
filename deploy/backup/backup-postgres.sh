#!/bin/sh
set -eu

umask 077

backup_dir=${MINEGUARD_BACKUP_DIR:-/var/backups/mineguard}
recipient=${MINEGUARD_BACKUP_AGE_RECIPIENT:-}
signing_key_file=${MINEGUARD_BACKUP_MINISIGN_SECRET_KEY_FILE:-}
retention_days=${MINEGUARD_BACKUP_LOCAL_RETENTION_DAYS:-14}
minimum_free_bytes=${MINEGUARD_BACKUP_MIN_FREE_BYTES:-1073741824}

case "$backup_dir" in
  ""|"/"|[!/]*)
    echo "MINEGUARD_BACKUP_DIR must be a dedicated absolute directory" >&2
    exit 2
    ;;
esac

if [ -z "$recipient" ]; then
  echo "MINEGUARD_BACKUP_AGE_RECIPIENT is required" >&2
  exit 2
fi
if [ -z "$signing_key_file" ] || [ ! -f "$signing_key_file" ]; then
  echo "MINEGUARD_BACKUP_MINISIGN_SECRET_KEY_FILE must name a signing key" >&2
  exit 2
fi
case "$retention_days" in
  ""|*[!0-9]*)
    echo "MINEGUARD_BACKUP_LOCAL_RETENTION_DAYS must be a non-negative integer" >&2
    exit 2
    ;;
esac
case "$minimum_free_bytes" in
  ""|*[!0-9]*)
    echo "MINEGUARD_BACKUP_MIN_FREE_BYTES must be a non-negative integer" >&2
    exit 2
    ;;
esac
if [ "${#minimum_free_bytes}" -gt 18 ]; then
  echo "MINEGUARD_BACKUP_MIN_FREE_BYTES is too large" >&2
  exit 2
fi

for command_name in pg_dump pg_restore psql sha256sum age minisign tar wc find grep flock df awk; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is missing: $command_name" >&2
    exit 2
  fi
done

mkdir -p "$backup_dir"
lock_file="$backup_dir/.mineguard-backup.lock"
exec 9>"$lock_file"
if ! flock -n 9; then
  echo "another MineGuard backup is already running" >&2
  exit 1
fi

prune_local_backup_state() {
  for uploaded_file in "$backup_dir"/mineguard-*.uploaded; do
    [ -f "$uploaded_file" ] || continue
    if find "$uploaded_file" -mtime "+$retention_days" -print | grep -q .; then
      uploaded_base=${uploaded_file%.uploaded}
      rm -f \
        "$uploaded_base.age" \
        "$uploaded_base.age.sha256" \
        "$uploaded_base.age.minisig" \
        "$uploaded_base.ready" \
        "$uploaded_file"
    fi
  done
  find "$backup_dir" -maxdepth 1 -type f -name 'mineguard-*.partial' \
    -mtime +1 -delete
}

prune_local_backup_state
database_bytes=$(psql -X -v ON_ERROR_STOP=1 -Atqc \
  "SELECT pg_database_size(current_database())")
case "$database_bytes" in
  ""|*[!0-9]*)
    echo "database size preflight returned an invalid value" >&2
    exit 1
    ;;
esac
if [ "${#database_bytes}" -gt 18 ]; then
  echo "database is too large for the backup size preflight" >&2
  exit 1
fi
available_kib=$(df -Pk "$backup_dir" | awk 'NR == 2 { print $4 }')
case "$available_kib" in
  ""|*[!0-9]*)
    echo "backup filesystem free-space preflight failed" >&2
    exit 1
    ;;
esac
required_bytes=$(awk \
  -v database_bytes="$database_bytes" \
  -v reserve_bytes="$minimum_free_bytes" \
  'BEGIN { printf "%.0f", database_bytes * 3 + reserve_bytes }')
if ! awk \
  -v available_kib="$available_kib" \
  -v required_bytes="$required_bytes" \
  'BEGIN { exit ! (available_kib * 1024 >= required_bytes) }'; then
  echo "backup filesystem has insufficient free space: required_bytes=$required_bytes" >&2
  exit 1
fi
work_dir=$(mktemp -d "$backup_dir/.mineguard-backup.XXXXXX")
artifacts_owned=0
cleanup() {
  if [ "$artifacts_owned" -eq 1 ]; then
    [ -z "${encrypted_partial:-}" ] || rm -f "$encrypted_partial"
    [ -z "${checksum_partial:-}" ] || rm -f "$checksum_partial"
    [ -z "${ready_partial:-}" ] || rm -f "$ready_partial"
    [ -z "${signature_partial:-}" ] || rm -f "$signature_partial"
    if [ -n "${ready_file:-}" ] && [ ! -f "$ready_file" ]; then
      [ -z "${encrypted_file:-}" ] || rm -f "$encrypted_file"
      [ -z "${checksum_file:-}" ] || rm -f "$checksum_file"
      [ -z "${signature_file:-}" ] || rm -f "$signature_file"
    fi
  fi
  [ -z "${metrics_partial:-}" ] || rm -f "$metrics_partial"
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
base_name="mineguard-$stamp"
dump_file="$work_dir/database.dump"
archive_file="$work_dir/$base_name.tar"
encrypted_partial="$backup_dir/$base_name.age.partial"
encrypted_file="$backup_dir/$base_name.age"
checksum_partial="$backup_dir/$base_name.age.sha256.partial"
checksum_file="$backup_dir/$base_name.age.sha256"
signature_partial="$backup_dir/$base_name.age.minisig.partial"
signature_file="$backup_dir/$base_name.age.minisig"
ready_partial="$backup_dir/$base_name.ready.partial"
ready_file="$backup_dir/$base_name.ready"
metrics_partial="$backup_dir/.mineguard-backup-metrics.$$"
metrics_file="$backup_dir/mineguard-backup.prom"

for reserved_path in \
  "$encrypted_partial" "$encrypted_file" \
  "$checksum_partial" "$checksum_file" \
  "$signature_partial" "$signature_file" \
  "$ready_partial" "$ready_file"; do
  if [ -e "$reserved_path" ]; then
    echo "backup artifact name collision; refusing to overwrite" >&2
    exit 1
  fi
done
artifacts_owned=1

pg_dump \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-acl \
  --file="$dump_file"
pg_restore --list "$dump_file" >/dev/null
dump_hash=$(sha256sum "$dump_file")
dump_hash=${dump_hash%% *}
printf '%s  %s\n' "$dump_hash" database.dump >"$work_dir/database.dump.sha256"

{
  echo "created_at=$created_at"
  echo "database=${PGDATABASE:-unknown}"
  echo "format=postgres-custom"
  echo "encryption=age"
} >"$work_dir/metadata.txt"

tar -C "$work_dir" -cf "$archive_file" \
  database.dump database.dump.sha256 metadata.txt
age --recipient "$recipient" --output "$encrypted_partial" "$archive_file"
encrypted_hash=$(sha256sum "$encrypted_partial")
encrypted_hash=${encrypted_hash%% *}
printf '%s  %s\n' "$encrypted_hash" "$(basename "$encrypted_file")" \
  >"$checksum_partial"
minisign -S -q \
  -s "$signing_key_file" \
  -m "$encrypted_partial" \
  -x "$signature_partial"
mv "$encrypted_partial" "$encrypted_file"
mv "$checksum_partial" "$checksum_file"
mv "$signature_partial" "$signature_file"

{
  echo "created_at=$created_at"
  echo "artifact=$(basename "$encrypted_file")"
  echo "checksum=$(basename "$checksum_file")"
  echo "signature=$(basename "$signature_file")"
} >"$ready_partial"
mv "$ready_partial" "$ready_file"

artifact_bytes=$(wc -c <"$encrypted_file")
{
  echo "# TYPE mineguard_backup_last_success_timestamp_seconds gauge"
  echo "mineguard_backup_last_success_timestamp_seconds $(date +%s)"
  echo "# TYPE mineguard_backup_artifact_bytes gauge"
  echo "mineguard_backup_artifact_bytes $artifact_bytes"
} >"$metrics_partial"
mv "$metrics_partial" "$metrics_file"

prune_local_backup_state

echo "$ready_file"
