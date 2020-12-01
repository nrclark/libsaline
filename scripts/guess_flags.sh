#!/bin/sh

set -eu

CC="${CC:-gcc}"
BLACKLIST="${BLACKLIST:-}"
WORKDIR="$(mktemp -d -p.)"

#------------------------------------------------------------------------------#

cleanup() {
    exit_code="$?"
    rm -rf "$WORKDIR"

    if [ $exit_code -ne 0 ]; then
        echo "Script failed with exit-code $exit_code" >&2
        exit $exit_code
    fi
}

mkdir -p "$WORKDIR" && cd "$WORKDIR" && WORKDIR="$(pwd)"
trap cleanup INT TERM QUIT EXIT

#------------------------------------------------------------------------------#

if ! eval "$CC -v" 2>&1 | grep "version " | grep -q gcc; then
    echo "Error: this script only supports GCC." >&2
    exit 1
fi

eval "$CC -Wall -Wextra -pedantic -Q --help=warning" | \
    grep -P "(disabled|[=] )" | \
    grep -Po "[-]W[^ \t=]+" | sort | uniq > flags.temp.init

echo "int main(void) { return 0;}" > flags.temp.c

eval "$CC $(tr '\n' ' ' <flags.temp.init) flags.temp.c -o /dev/null 2>&1" | \
    grep "error: " | grep -oP "[-]W[a-zA-Z0-9_-]+" | sort | uniq > \
    flags.temp.blacklist

grep -vFf flags.temp.blacklist flags.temp.init > \
    flags.temp.works

eval "$CC $(tr '\n' ' ' <flags.temp.works) flags.temp.c -o /dev/null 2>&1" | \
    grep -P "is valid for [^ ]+ but not for C" | \
    ( grep -oP "[-]W[a-zA-Z0-9_+-]+" || true ) > flags.temp.blacklist

grep -vFf flags.temp.blacklist flags.temp.works > flags.temp.ok

echo "$BLACKLIST" | tr ' ' '\n' | sort | uniq | sed -r 's/[ \t]//g' | \
    sed '/^$/d' > blacklist

grep -vFf blacklist flags.temp.ok
