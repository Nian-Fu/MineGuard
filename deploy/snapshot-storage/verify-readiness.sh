#!/bin/sh
set -eu

umask 077

bucket=${MINEGUARD_SNAPSHOT_STORAGE_BUCKET:-}
endpoint=${MINEGUARD_SNAPSHOT_STORAGE_ENDPOINT_URL:-}
retention_days=${MINEGUARD_EVENT_SNAPSHOT_RETENTION_DAYS:-90}

case "$bucket" in
  ""|*[!a-z0-9.-]*|.*|*.|*..*|*.-*|*-.*)
    echo "MINEGUARD_SNAPSHOT_STORAGE_BUCKET is invalid" >&2
    exit 2
    ;;
esac
if [ "${#bucket}" -lt 3 ] || [ "${#bucket}" -gt 63 ]; then
  echo "MINEGUARD_SNAPSHOT_STORAGE_BUCKET must contain 3-63 characters" >&2
  exit 2
fi
case "$retention_days" in
  ""|*[!0-9]*)
    echo "MINEGUARD_EVENT_SNAPSHOT_RETENTION_DAYS must be an integer" >&2
    exit 2
    ;;
esac
if [ "$retention_days" -lt 7 ] || [ "$retention_days" -gt 3650 ]; then
  echo "MINEGUARD_EVENT_SNAPSHOT_RETENTION_DAYS must be between 7 and 3650" >&2
  exit 2
fi
if [ -n "$endpoint" ]; then
  case "$endpoint" in
    https://*) ;;
    *)
      echo "snapshot storage readiness endpoint must use HTTPS" >&2
      exit 2
      ;;
  esac
  authority=${endpoint#https://}
  case "$authority" in
    ""|*/*|*\?*|*\#*|*[[:space:]]*|*@*|*\;*|*\"*|*\'*)
      echo "snapshot storage readiness endpoint must be an explicit HTTPS origin" >&2
      exit 2
      ;;
  esac
  case "$authority" in
    *:*)
      endpoint_host=${authority%%:*}
      endpoint_port=${authority#*:}
      case "$endpoint_port" in
        ""|*[!0-9]*)
          echo "snapshot storage readiness endpoint contains an invalid port" >&2
          exit 2
          ;;
      esac
      if [ "$endpoint_port" -lt 1 ] || [ "$endpoint_port" -gt 65535 ]; then
        echo "snapshot storage readiness endpoint port is out of range" >&2
        exit 2
      fi
      ;;
    *) endpoint_host=$authority ;;
  esac
  case "$endpoint_host" in
    ""|.*|*..*|*[!A-Za-z0-9.-]*)
      echo "snapshot storage readiness endpoint contains an invalid host" >&2
      exit 2
      ;;
  esac
fi
for command_name in aws jq; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is missing: $command_name" >&2
    exit 2
  fi
done

s3api() {
  if [ -n "$endpoint" ]; then
    aws --no-cli-pager --endpoint-url "$endpoint" s3api "$@"
  else
    aws --no-cli-pager s3api "$@"
  fi
}

lifecycle=$(s3api get-bucket-lifecycle-configuration \
  --bucket "$bucket" --output json)
if ! printf '%s\n' "$lifecycle" | jq -e \
  --argjson days "$retention_days" '
    def hold_false:
      .Filter.And as $and
      | ($and | type) == "object"
      and (($and | keys | sort) == ["Prefix", "Tags"])
      and $and.Prefix == "snapshots/"
      and $and.Tags == [{"Key":"mineguard-legal-hold", "Value":"false"}];
    any(.Rules[]?;
      .Status == "Enabled"
      and hold_false
      and .Expiration.Days == $days
    )
  ' >/dev/null; then
  echo "snapshot lifecycle has no exact enabled current-version retention rule" >&2
  exit 3
fi

if ! printf '%s\n' "$lifecycle" | jq -e '
    def prefix:
      .Filter.And.Prefix // .Filter.Prefix // .Prefix // "";
    def hold_false:
      any(([
        .Filter.And.Tags[]?,
        .Filter.Tag?
      ] | .[]?);
        .Key == "mineguard-legal-hold" and .Value == "false"
      );
    def deletes_objects:
      (.Expiration.Days? != null)
      or (.Expiration.Date? != null)
      or (.NoncurrentVersionExpiration? != null);
    all(.Rules[]?;
      prefix as $prefix
      | if .Status == "Enabled"
        and deletes_objects
        and (($prefix | startswith("snapshots/")) or ("snapshots/" | startswith($prefix)))
      then hold_false
      else true
      end
    )
  ' >/dev/null; then
  echo "an overlapping expiration rule can delete a legal-hold snapshot" >&2
  exit 3
fi

versioning=$(s3api get-bucket-versioning --bucket "$bucket" --output json)
version_status=$(printf '%s\n' "$versioning" | jq -r '.Status // "Disabled"')
case "$version_status" in
  Disabled) ;;
  Enabled|Suspended)
    if ! printf '%s\n' "$lifecycle" | jq -e \
      --argjson days "$retention_days" '
        def hold_false:
          .Filter.And.Prefix == "snapshots/"
          and .Filter.And.Tags == [{"Key":"mineguard-legal-hold", "Value":"false"}];
        any(.Rules[]?;
          .Status == "Enabled"
          and hold_false
          and .NoncurrentVersionExpiration.NoncurrentDays == $days
        )
        and any(.Rules[]?;
          .Status == "Enabled"
          and ((.Filter.Prefix // .Prefix // "") == "snapshots/")
          and .Expiration.ExpiredObjectDeleteMarker == true
        )
      ' >/dev/null; then
      echo "versioned snapshot storage lacks noncurrent or delete-marker cleanup" >&2
      exit 3
    fi
    ;;
  *)
    echo "snapshot bucket returned an unknown versioning status" >&2
    exit 3
    ;;
esac

encryption=$(s3api get-bucket-encryption --bucket "$bucket" --output json)
if ! printf '%s\n' "$encryption" | jq -e '
    any(.ServerSideEncryptionConfiguration.Rules[]?;
      .ApplyServerSideEncryptionByDefault.SSEAlgorithm == "AES256"
      or .ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms"
    )
  ' >/dev/null; then
  echo "snapshot bucket has no approved default server-side encryption" >&2
  exit 3
fi

public_access=$(s3api get-public-access-block --bucket "$bucket" --output json)
if ! printf '%s\n' "$public_access" | jq -e '
    .PublicAccessBlockConfiguration
    | .BlockPublicAcls == true
      and .IgnorePublicAcls == true
      and .BlockPublicPolicy == true
      and .RestrictPublicBuckets == true
  ' >/dev/null; then
  echo "snapshot bucket public access block is incomplete" >&2
  exit 3
fi

policy=$(s3api get-bucket-policy --bucket "$bucket" --query Policy --output text)
if ! printf '%s\n' "$policy" | jq -e --arg bucket "$bucket" '
    def unconditional_transport_deny:
      try (
        .Effect == "Deny"
        and .Principal == "*"
        and (.Condition | type) == "object"
        and ((.Condition | keys | sort) == ["Bool"])
        and (.Condition.Bool | type) == "object"
        and ((.Condition.Bool | keys | sort) == ["aws:SecureTransport"])
        and ((.Condition.Bool["aws:SecureTransport"] | tostring) == "false")
        and ([.Action] | flatten | any(.[]; . == "*" or . == "s3:*"))
      ) catch false;
    [
      ([.Statement] | flatten)[]?
      | select(unconditional_transport_deny)
      | [.Resource]
      | flatten
      | .[]
    ] as $resources
    | ($resources | index("*") != null)
      or (
        ($resources | index("arn:aws:s3:::" + $bucket) != null)
        and ($resources | index("arn:aws:s3:::" + $bucket + "/*") != null)
      )
  ' >/dev/null; then
  echo "snapshot bucket policy does not unconditionally deny insecure transport for all principals" >&2
  exit 3
fi

echo "snapshot_storage_readiness=passed"
echo "bucket=$bucket"
echo "retention_days=$retention_days"
echo "versioning=$version_status"
