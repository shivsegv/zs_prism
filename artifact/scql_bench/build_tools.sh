#!/bin/sh
# Build scdbclient and scqltool from the SCQL release used for the image.
set -eu
cd "$(dirname "$0")"
TMP=$(mktemp -d)
git clone -q --depth 1 --branch 1.0.0b1 https://github.com/secretflow/scql "$TMP/scql"
mkdir -p bin
(cd "$TMP/scql" && go build -o "$OLDPWD/bin/scdbclient" ./cmd/scdbclient && go build -o "$OLDPWD/bin/scqltool" ./cmd/scqltool)
rm -rf "$TMP"
