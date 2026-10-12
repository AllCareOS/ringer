#!/bin/sh
# report.md must state the stage-2 sum
want=$(tr -d ' \r\n' < "$1/sum.txt")
grep -q "Total: $want" report.md && echo "report ok" || { echo "report.md missing 'Total: $want'"; exit 1; }
