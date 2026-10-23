#!/usr/bin/env bash
set -euo pipefail
DB="${WAF_DB_PATH:-data/detections.db}"
DEST="${1:-backups}"
mkdir -p "$DEST"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [ ! -f "$DB" ]; then
  echo "Database not found: $DB" >&2
  exit 1
fi
sqlite3 "$DB" ".backup '$DEST/detections-$STAMP.db'"
gzip -f "$DEST/detections-$STAMP.db"
find "$DEST" -name 'detections-*.db.gz' -mtime +30 -delete
echo "Backup written: $DEST/detections-$STAMP.db.gz"
