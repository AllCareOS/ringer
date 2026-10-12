#!/bin/sh
# numbers.txt must hold 1..5, one per line
got="$(tr -d ' \r' < numbers.txt 2>/dev/null | sed '/^$/d')"
if [ "$got" = "$(printf '1\n2\n3\n4\n5')" ]; then echo "numbers ok"; else echo "numbers.txt wrong: $got"; exit 1; fi
