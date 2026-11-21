#!/bin/bash
# Downloads DB-IP Lite City + ASN (free, CC BY 4.0). About 65 MB.
# DB-IP updates them monthly, re-run to refresh.
set -euo pipefail
cd "$(dirname "$0")/data"
month=$(date +%Y-%m)
for kind in city asn; do
  url="https://download.db-ip.com/free/dbip-${kind}-lite-${month}.mmdb.gz"
  echo "Downloading $url"
  if ! curl -fSL --progress-bar -o "${kind}.mmdb.gz" "$url"; then
    prev=$(date -v-1m +%Y-%m)   # new month's file may not be published yet
    curl -fSL --progress-bar -o "${kind}.mmdb.gz" "https://download.db-ip.com/free/dbip-${kind}-lite-${prev}.mmdb.gz"
  fi
  gunzip -f "${kind}.mmdb.gz"
  mv -f "${kind}.mmdb" "dbip-${kind}-lite.mmdb"
done
ls -lh dbip-*.mmdb
echo "Done. Restart MAC SIEM to load the new data."
