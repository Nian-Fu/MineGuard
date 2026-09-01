#!/bin/sh
set -eu

umask 077

restore_service=${MINEGUARD_PITR_PGSERVICE:-}
tool=${MINEGUARD_PITR_TOOL:-}
stanza=${MINEGUARD_PITR_STANZA:-}
max_archive_age=${MINEGUARD_PITR_MAX_ARCHIVE_AGE_SECONDS:-600}

case "$restore_service" in
  ""|*[!A-Za-z0-9_.-]*)
    echo "MINEGUARD_PITR_PGSERVICE must be a single pg_service name" >&2
    exit 2
    ;;
esac
case "$tool" in
  pgbackrest|wal-g|barman) ;;
  *)
    echo "MINEGUARD_PITR_TOOL must be pgbackrest, wal-g, or barman" >&2
    exit 2
    ;;
esac
case "$max_archive_age" in
  ""|*[!0-9]*)
    echo "MINEGUARD_PITR_MAX_ARCHIVE_AGE_SECONDS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$max_archive_age" -lt 60 ] || [ "$max_archive_age" -gt 86400 ]; then
  echo "MINEGUARD_PITR_MAX_ARCHIVE_AGE_SECONDS must be between 60 and 86400" >&2
  exit 2
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "required command is missing: psql" >&2
  exit 2
fi

settings=$(psql "service=$restore_service" -X -v ON_ERROR_STOP=1 -AtF '|' -c "
  SELECT
    current_setting('archive_mode'),
    current_setting('wal_level'),
    current_setting('full_page_writes'),
    current_setting('data_checksums'),
    current_setting('archive_timeout'),
    current_setting('archive_command'),
    current_setting('archive_library');
")
IFS='|' read -r archive_mode wal_level full_page_writes data_checksums \
  archive_timeout archive_command archive_library <<EOF
$settings
EOF

if [ "$archive_mode" != "on" ] \
  || { [ "$wal_level" != "replica" ] && [ "$wal_level" != "logical" ]; } \
  || [ "$full_page_writes" != "on" ] \
  || [ "$data_checksums" != "on" ]; then
  echo "PostgreSQL WAL safety settings do not satisfy the PITR contract" >&2
  exit 3
fi
if [ -z "$archive_command" ] && [ -z "$archive_library" ]; then
  echo "PostgreSQL has no archive_command or archive_library" >&2
  exit 3
fi

archive_timeout_seconds=$(psql "service=$restore_service" -X -v ON_ERROR_STOP=1 -Atqc \
  "SELECT extract(epoch FROM current_setting('archive_timeout')::interval)::bigint")
if [ "$archive_timeout_seconds" -le 0 ] \
  || [ "$archive_timeout_seconds" -gt "$max_archive_age" ]; then
  echo "archive_timeout does not bound the approved recovery point window" >&2
  exit 3
fi

archiver=$(psql "service=$restore_service" -X -v ON_ERROR_STOP=1 -AtF '|' -c "
  SELECT
    archived_count,
    failed_count,
    COALESCE(extract(epoch FROM clock_timestamp() - last_archived_time)::bigint, -1),
    CASE
      WHEN last_failed_time IS NULL THEN 0
      WHEN last_archived_time IS NULL OR last_failed_time > last_archived_time THEN 1
      ELSE 0
    END,
    COALESCE(last_archived_wal, '');
  FROM pg_stat_archiver;
")
IFS='|' read -r archived_count failed_count archive_age unresolved_failure \
  last_archived_wal <<EOF
$archiver
EOF
if [ "$archived_count" -le 0 ] \
  || [ "$archive_age" -lt 0 ] \
  || [ "$archive_age" -gt "$max_archive_age" ] \
  || [ "$unresolved_failure" -ne 0 ] \
  || [ -z "$last_archived_wal" ]; then
  echo "PostgreSQL WAL archiver is stale or has an unresolved failure" >&2
  exit 4
fi

case "$tool" in
  pgbackrest)
    case "$stanza" in
      ""|*[!A-Za-z0-9_.-]*)
        echo "MINEGUARD_PITR_STANZA must name the pgBackRest stanza" >&2
        exit 2
        ;;
    esac
    for command_name in pgbackrest jq; do
      command -v "$command_name" >/dev/null 2>&1 || {
        echo "required command is missing: $command_name" >&2
        exit 2
      }
    done
    pgbackrest --stanza="$stanza" check >/dev/null
    pgbackrest --stanza="$stanza" info --output=json \
      | jq -e 'type == "array" and length == 1 and ((.[0].backup | type) == "array") and (.[0].backup | length > 0)' \
        >/dev/null
    ;;
  wal-g)
    for command_name in wal-g jq; do
      command -v "$command_name" >/dev/null 2>&1 || {
        echo "required command is missing: $command_name" >&2
        exit 2
      }
    done
    wal-g backup-list --json \
      | jq -e 'type == "array" and length > 0' >/dev/null
    ;;
  barman)
    case "$stanza" in
      ""|*[!A-Za-z0-9_.-]*)
        echo "MINEGUARD_PITR_STANZA must name the Barman server" >&2
        exit 2
        ;;
    esac
    command -v barman >/dev/null 2>&1 || {
      echo "required command is missing: barman" >&2
      exit 2
    }
    barman check "$stanza" >/dev/null
    backups=$(barman list-backups "$stanza" --minimal)
    if [ -z "$backups" ]; then
      echo "Barman reports no physical backup" >&2
      exit 5
    fi
    ;;
esac

echo "pitr_readiness=passed"
echo "tool=$tool"
echo "archived_count=$archived_count"
echo "failed_count=$failed_count"
echo "archive_age_seconds=$archive_age"
echo "last_archived_wal=$last_archived_wal"
