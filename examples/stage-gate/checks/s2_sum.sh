#!/bin/sh
# sum.txt must equal the sum of the stage-1 snapshot numbers
src="$1/numbers.txt"
want=$(awk '{s+=$1} END {print s}' "$src")
got=$(tr -d ' \r\n' < sum.txt 2>/dev/null)
if [ "$got" = "$want" ]; then echo "sum ok ($got)"; else echo "sum.txt is '$got', expected $want from $src"; exit 1; fi
