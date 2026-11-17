#!/bin/bash
# check-client-copy.sh DIR: a caller that keeps a copy of the decode service's API and checks (MediaProvider before it
# links de.diamaneos.sanitizer.decode-client) must keep exact copies. Compares every AIDL file and DecodeChecks.java
# under DIR with this repository's, by content. Exit 0 when all match.
set -u
DIR=${1:?directory with the copy}
HERE=$(cd "$(dirname "$0")/.." && pwd)
rc=0
for f in $(cd "$HERE" && ls aidl/de/diamaneos/sanitizer/decode/*.aidl client/de/diamaneos/sanitizer/decode/DecodeChecks.java); do
  name=$(basename "$f")
  copy=$(find "$DIR" -name "$name" -path '*de/diamaneos/sanitizer/decode/*' | head -n 1)
  if [ -z "$copy" ]; then echo "missing: $name"; rc=1
  elif ! cmp -s "$HERE/$f" "$copy"; then echo "differs: $name ($copy)"; rc=1
  else echo "same: $name"; fi
done
exit $rc
