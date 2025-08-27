#!/usr/bin/env bash

output_file="FullPSIClientBenchmark.results"

# (Re)create the results file
: >"$output_file"

for p in {10..100..10}; do
  echo "=== p=$p ===" >>"$output_file"
  ../build/FullPSIClientBenchmark -p "$p" >>"$output_file"
done
