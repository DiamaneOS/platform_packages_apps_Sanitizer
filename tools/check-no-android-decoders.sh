#!/bin/bash
# check-no-android-decoders.sh ALLOW DIR...: no new call of Android's in-process image decoders where untrusted
# images arrive (MediaProvider, and in frameworks/base SystemUI, Shell, the notification and wallpaper services).
# Those decode in the decode service's VM. A rebase can bring a new upstream call site (a picker feature, a thumbnail
# path) that decodes with Android's decoders again, and this finds it.
#
# Searches the Java and Kotlin sources under each DIR, tests left out, for BitmapFactory.decode*,
# ImageDecoder.decodeBitmap and decodeDrawable, BitmapRegionDecoder, ThumbnailUtils.create*Thumbnail,
# Drawable.createFromStream, createFromPath and createFromResourceStream, and ExifInterface's getThumbnailBitmap().
# ALLOW lists the calls meant to stay, one per line: "PATH: TEXT # reason", PATH as printed here (relative to the
# current directory) and TEXT a part of that source line. Exit 1 when a call is not allowed, or an allowed one is
# gone (the list must shrink with the code).
set -u
ALLOW=${1:?allow list}
shift
[ $# -ge 1 ] || { echo "usage: $0 ALLOW DIR..." >&2; exit 2; }
pattern='BitmapFactory\.decode|ImageDecoder\.decode(Bitmap|Drawable)|BitmapRegionDecoder|ThumbnailUtils\.create[A-Za-z]*Thumbnail|Drawable\.createFrom(Stream|Path|ResourceStream)|getThumbnailBitmap\(\)'
allowed=$(grep -v '^\s*#' "$ALLOW" | grep -v '^\s*$' | sed 's/ # .*$//')
found=$(grep -rnE "$pattern" --include='*.java' --include='*.kt' "$@" 2>/dev/null \
  | grep -vE '/(tests?|androidTest|testapp|testing|benchmark|robotests|multivalentTests)/' \
  | grep -vE '^[^:]+:[0-9]+:\s*(\*|//|/\*)')
rc=0
used=""
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  path=${hit%%:*}
  text=${hit#*:*:}
  ok=0
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    apath=${a%%: *}
    atext=${a#*: }
    if [ "$apath" = "$path" ] && [[ "$text" == *"$atext"* ]]; then ok=1; used="$used
$a"; break; fi
  done <<< "$allowed"
  if [ $ok = 0 ]; then echo "not allowed: $hit"; rc=1; fi
done <<< "$found"
while IFS= read -r a; do
  [ -n "$a" ] || continue
  grep -qxF "$a" <<< "$used" || { echo "allowed but gone (remove it from $ALLOW): $a"; rc=1; }
done <<< "$allowed"
[ $rc = 0 ] && echo "ok: no Android decoder call outside $ALLOW ($(grep -c . <<< "$used" ) allowed)"
exit $rc
