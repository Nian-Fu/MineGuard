#!/bin/sh
set -eu

umask 077

backup_dir=${MINEGUARD_BACKUP_DIR:-/var/backups/mineguard}
remote=${MINEGUARD_BACKUP_RCLONE_REMOTE:-}
poll_seconds=${MINEGUARD_BACKUP_UPLOAD_POLL_SECONDS:-60}

case "$backup_dir" in
  ""|"/"|[!/]*)
    echo "MINEGUARD_BACKUP_DIR must be a dedicated absolute directory" >&2
    exit 2
    ;;
esac
if [ -z "$remote" ]; then
  echo "MINEGUARD_BACKUP_RCLONE_REMOTE is required" >&2
  exit 2
fi
case "$poll_seconds" in
  ""|*[!0-9]*)
    echo "MINEGUARD_BACKUP_UPLOAD_POLL_SECONDS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$poll_seconds" -lt 5 ] || [ "$poll_seconds" -gt 3600 ]; then
  echo "MINEGUARD_BACKUP_UPLOAD_POLL_SECONDS must be between 5 and 3600" >&2
  exit 2
fi
if ! command -v rclone >/dev/null 2>&1; then
  echo "required command is missing: rclone" >&2
  exit 2
fi

remote=${remote%/}
stopping=false
metrics_partial="$backup_dir/.mineguard-upload-metrics.$$"
metrics_file="$backup_dir/mineguard-backup-upload.prom"
trap 'stopping=true; rm -f "$metrics_partial"' HUP INT TERM EXIT
attempt=0

upload_file() {
  source_file=$1
  rclone copyto \
    --checksum \
    --immutable \
    --contimeout 10s \
    --timeout 1m \
    --retries 3 \
    --low-level-retries 10 \
    "$source_file" "$remote/$(basename "$source_file")"
}

while [ "$stopping" = false ]; do
  failed=false
  for ready_file in "$backup_dir"/mineguard-*.ready; do
    [ -f "$ready_file" ] || continue
    backup_base=${ready_file%.ready}
    artifact_file="$backup_base.age"
    checksum_file="$backup_base.age.sha256"
    signature_file="$backup_base.age.minisig"
    uploaded_file="$backup_base.uploaded"
    [ ! -f "$uploaded_file" ] || continue
    if [ ! -f "$artifact_file" ] \
      || [ ! -f "$checksum_file" ] \
      || [ ! -f "$signature_file" ]; then
      echo "ready backup is incomplete: $ready_file" >&2
      failed=true
      break
    fi
    if upload_file "$artifact_file" \
      && upload_file "$checksum_file" \
      && upload_file "$signature_file" \
      && upload_file "$ready_file"; then
      touch "$uploaded_file"
      attempt=0
      echo "uploaded $(basename "$backup_base")"
    else
      failed=true
      break
    fi
  done

  if [ "$failed" = true ]; then
    attempt=$((attempt + 1))
    exponent=$attempt
    [ "$exponent" -le 8 ] || exponent=8
    delay=$((2 ** exponent))
    [ "$delay" -le 300 ] || delay=300
    echo "backup upload failed; retrying in ${delay}s" >&2
  else
    attempt=0
    delay=$poll_seconds
  fi

  pending=0
  for ready_file in "$backup_dir"/mineguard-*.ready; do
    [ -f "$ready_file" ] || continue
    [ -f "${ready_file%.ready}.uploaded" ] || pending=$((pending + 1))
  done
  if [ "$failed" = true ]; then
    healthy=0
  else
    healthy=1
  fi
  {
    echo "# TYPE mineguard_backup_upload_last_check_timestamp_seconds gauge"
    echo "mineguard_backup_upload_last_check_timestamp_seconds $(date +%s)"
    echo "# TYPE mineguard_backup_upload_healthy gauge"
    echo "mineguard_backup_upload_healthy $healthy"
    echo "# TYPE mineguard_backup_upload_consecutive_failures gauge"
    echo "mineguard_backup_upload_consecutive_failures $attempt"
    echo "# TYPE mineguard_backup_upload_pending gauge"
    echo "mineguard_backup_upload_pending $pending"
  } >"$metrics_partial"
  mv "$metrics_partial" "$metrics_file"
  [ "$stopping" = false ] || break
  sleep "$delay" || true
done
