#!/bin/sh
set -eu

origin=${MINEGUARD_SNAPSHOT_CSP_ORIGIN:-}
if [ -z "$origin" ]; then
  exit 0
fi
case "$origin" in
  https://*) ;;
  *)
    echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN must be an explicit HTTPS origin" >&2
    exit 1
    ;;
esac
authority=${origin#https://}
case "$authority" in
  ""|*/*|*\?*|*\#*|*[[:space:]]*|*\;*|*\"*|*\'*)
    echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN must not contain a path, query, fragment, whitespace, or quotes" >&2
    exit 1
    ;;
esac
case "$authority" in
  *:*)
    host=${authority%%:*}
    port=${authority#*:}
    case "$port" in
      ""|*[!0-9]*)
        echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN contains an invalid port" >&2
        exit 1
        ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
      echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN port is out of range" >&2
      exit 1
    fi
    ;;
  *) host=$authority ;;
esac
case "$host" in
  ""|.*|*..*|*[!A-Za-z0-9.*-]*)
    echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN contains an invalid host" >&2
    exit 1
    ;;
esac
case "$host" in
  *\**)
    case "$host" in
      \*.*) ;;
      *)
        echo "MINEGUARD_SNAPSHOT_CSP_ORIGIN wildcard must be the first label" >&2
        exit 1
        ;;
    esac
    ;;
esac
