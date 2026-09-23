#!/bin/sh
# Restore only a supplied disposable source archive. No database or upstream I/O.
set -eu
if [ "$#" -ne 1 ] && { [ "$#" -ne 2 ] || [ "$2" != "--previous-candidate" ]; }; then
    printf '%s\n' 'usage: ROLLBACK.sh TARGET_COPY.zip [--previous-candidate]' >&2
    exit 64
fi
here=$(CDPATH= cd "$(dirname "$0")" && pwd)
case "$1" in
    /*) target=$1 ;;
    *) target=$(pwd)/$1 ;;
esac
if [ "$#" -eq 2 ]; then
    cp "$here/generation-egress/BASELINE_INPUT.zip" "$target"
    printf '%s\n' 'Restored previous candidate source archive; databases and upstream resources were not modified.'
else
    cp "$here/baseline.source.zip" "$target"
    printf '%s\n' 'Restored pristine source archive; databases and upstream resources were not modified.'
fi
