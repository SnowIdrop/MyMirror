#!/bin/sh
# Restore only a supplied disposable source archive. No database or upstream I/O.
set -eu
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: ROLLBACK.sh TARGET_COPY.zip' >&2
    exit 64
fi
here=$(CDPATH= cd "$(dirname "$0")" && pwd)
case "$1" in
    /*) target=$1 ;;
    *) target=$(pwd)/$1 ;;
esac
cp "$here/baseline.source.zip" "$target"
printf '%s\n' 'Restored pristine source archive; databases and upstream resources were not modified.'
