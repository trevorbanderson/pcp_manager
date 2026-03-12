#!/usr/bin/env bash
# run_migrations.sh — Apply pending SQL migrations to Azure PostgreSQL.
#
# Usage:
#   export PGPASSWORD="<db_password>"
#   ./migrations/run_migrations.sh <db_host> <db_user> <db_name>
#
# Requires: psql (postgresql-client)
# Safe to run multiple times — already-applied migrations are skipped.

set -euo pipefail

DB_HOST="${1:?Usage: $0 <db_host> <db_user> <db_name>}"
DB_USER="${2:?Usage: $0 <db_host> <db_user> <db_name>}"
DB_NAME="${3:?Usage: $0 <db_host> <db_user> <db_name>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== PCP Manager DB Migrations ==="
echo "  Host : $DB_HOST"
echo "  DB   : $DB_NAME"
echo "  User : $DB_USER"

PSQL="psql --host=$DB_HOST --username=$DB_USER --dbname=$DB_NAME --no-password"

# Create tracking table if it doesn't exist
$PSQL <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
SQL

echo ""
echo "Scanning for migrations in: $SCRIPT_DIR"

APPLIED=0
SKIPPED=0

for sql_file in $(ls "$SCRIPT_DIR"/*.sql 2>/dev/null | sort); do
    filename="$(basename "$sql_file")"

    # Check if already applied
    already_applied=$($PSQL -t -c "SELECT COUNT(*) FROM schema_migrations WHERE filename = '$filename';" | tr -d ' ')

    if [ "$already_applied" -gt 0 ]; then
        echo "  [SKIP]  $filename (already applied)"
        SKIPPED=$((SKIPPED + 1))
    else
        echo "  [RUN]   $filename ..."
        $PSQL -f "$sql_file"
        $PSQL -c "INSERT INTO schema_migrations (filename) VALUES ('$filename');"
        echo "  [DONE]  $filename"
        APPLIED=$((APPLIED + 1))
    fi
done

echo ""
echo "=== Migration complete: $APPLIED applied, $SKIPPED skipped ==="
