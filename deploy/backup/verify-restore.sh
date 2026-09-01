#!/bin/sh
set -eu

umask 077

encrypted_backup=${1:-}
identity_file=${MINEGUARD_BACKUP_AGE_IDENTITY_FILE:-}
verification_key_file=${MINEGUARD_BACKUP_MINISIGN_PUBLIC_KEY_FILE:-}
restore_service=${MINEGUARD_RESTORE_PGSERVICE:-}

if [ ! -f "$encrypted_backup" ]; then
  echo "usage: verify-restore.sh /path/to/mineguard-TIMESTAMP.age" >&2
  exit 2
fi
if [ -z "$identity_file" ] || [ ! -f "$identity_file" ]; then
  echo "MINEGUARD_BACKUP_AGE_IDENTITY_FILE must name an age identity file" >&2
  exit 2
fi
if [ -z "$verification_key_file" ] || [ ! -f "$verification_key_file" ]; then
  echo "MINEGUARD_BACKUP_MINISIGN_PUBLIC_KEY_FILE must name a verification key" >&2
  exit 2
fi
if [ -z "$restore_service" ]; then
  echo "MINEGUARD_RESTORE_PGSERVICE is required" >&2
  exit 2
fi
case "$restore_service" in
  *[!A-Za-z0-9_.-]* )
    echo "MINEGUARD_RESTORE_PGSERVICE must be a single pg_service name" >&2
    exit 2
    ;;
esac

for command_name in pg_restore psql sha256sum age minisign tar find wc; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is missing: $command_name" >&2
    exit 2
  fi
done

checksum_file="$encrypted_backup.sha256"
signature_file="$encrypted_backup.minisig"
if [ ! -f "$checksum_file" ]; then
  echo "encrypted artifact checksum is missing: $checksum_file" >&2
  exit 2
fi
if [ ! -f "$signature_file" ]; then
  echo "encrypted artifact signature is missing: $signature_file" >&2
  exit 2
fi

if ! minisign -V -q \
  -p "$verification_key_file" \
  -m "$encrypted_backup" \
  -x "$signature_file"; then
  echo "backup sender signature verification failed" >&2
  exit 2
fi

verify_sha256_record() {
  record_file=$1
  target_file=$2
  expected_name=$3
  if [ "$(wc -l <"$record_file")" != "1" ]; then
    echo "checksum record must contain exactly one line: $record_file" >&2
    exit 2
  fi
  expected_hash=
  listed_name=
  extra_field=
  IFS=' ' read -r expected_hash listed_name extra_field <"$record_file" || true
  case "$expected_hash" in
    ""|*[!0-9a-f]* )
      echo "checksum record contains an invalid SHA-256 value: $record_file" >&2
      exit 2
      ;;
  esac
  if [ "${#expected_hash}" != "64" ] \
    || [ "$listed_name" != "$expected_name" ] \
    || [ -n "$extra_field" ]; then
    echo "checksum record contains an unexpected target: $record_file" >&2
    exit 2
  fi
  actual_hash=$(sha256sum "$target_file")
  actual_hash=${actual_hash%% *}
  if [ "$actual_hash" != "$expected_hash" ]; then
    echo "checksum verification failed: $expected_name" >&2
    exit 2
  fi
}

verify_sha256_record \
  "$checksum_file" \
  "$encrypted_backup" \
  "$(basename "$encrypted_backup")"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/mineguard-restore.XXXXXX")
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

age --decrypt --identity "$identity_file" \
  --output "$work_dir/backup.tar" "$encrypted_backup"
archive_members=$(tar -tf "$work_dir/backup.tar")
expected_members=$(printf '%s\n' database.dump database.dump.sha256 metadata.txt)
if [ "$archive_members" != "$expected_members" ]; then
  echo "backup archive contains unexpected, missing, or reordered members" >&2
  exit 2
fi
tar -C "$work_dir" -xf "$work_dir/backup.tar" -- \
  database.dump database.dump.sha256 metadata.txt
for member in database.dump database.dump.sha256 metadata.txt; do
  regular_member=$(find "$work_dir/$member" -type f -links 1 -print 2>/dev/null)
  if [ "$regular_member" != "$work_dir/$member" ] \
    || [ -L "$work_dir/$member" ]; then
    echo "backup archive member must be a regular file: $member" >&2
    exit 2
  fi
done
verify_sha256_record \
  "$work_dir/database.dump.sha256" \
  "$work_dir/database.dump" \
  database.dump
pg_restore --list "$work_dir/database.dump" >/dev/null

existing_tables=$(psql "service=$restore_service" -Atqc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
if [ "$existing_tables" != "0" ]; then
  echo "restore target must be a dedicated empty database" >&2
  exit 3
fi

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
pg_restore \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-acl \
  --dbname="service=$restore_service" \
  "$work_dir/database.dump"

revision=$(psql "service=$restore_service" -Atqc \
  "SELECT version_num FROM alembic_version LIMIT 1")
critical_tables=$(psql "service=$restore_service" -Atqc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('users','cameras','events','audit_logs','face_templates','notification_deliveries')")
if [ -z "$revision" ] || [ "$critical_tables" != "6" ]; then
  echo "restore completed but structural verification failed" >&2
  exit 4
fi

psql "service=$restore_service" -v ON_ERROR_STOP=1 -Atqc \
  "SELECT 'users=' || count(*) FROM users UNION ALL SELECT 'cameras=' || count(*) FROM cameras UNION ALL SELECT 'events=' || count(*) FROM events UNION ALL SELECT 'audit_logs=' || count(*) FROM audit_logs"
completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "restore_verification=passed"
echo "source_artifact=$(basename "$encrypted_backup")"
echo "alembic_revision=$revision"
echo "started_at=$started_at"
echo "completed_at=$completed_at"
