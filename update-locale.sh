#!/bin/bash

set -e

NAME="ipa-gpo-install"
LOCALE_DIR="locale/ru/LC_MESSAGES"
SRC_DIR="src"

PO_FILE="${LOCALE_DIR}/${NAME}.po"
MO_FILE="${LOCALE_DIR}/${NAME}.mo"
TMP_POT_FILE="$(mktemp)"

xgettext --language=Python --keyword=_ --from-code=UTF-8 \
  --output="$TMP_POT_FILE" $(find "$SRC_DIR" -name '*.py')

msgmerge --update --backup=none "$PO_FILE" "$TMP_POT_FILE"

msgfmt --check --verbose "$PO_FILE" -o "$MO_FILE"

echo "$MO_FILE"

rm -f "$TMP_POT_FILE"