#!/usr/bin/env bash

output_file="FullPSIBenchmark.results"

# (Re)create the results file
: >"$output_file"

# Define the n values and p values
n_values=(100 1000 10000)
p_values=(10 20 30)

for n in "${n_values[@]}"; do
  for p in "${p_values[@]}"; do
    echo "=== b=fullhashx${n}.txt, -p ${p} ===" >>"$output_file"
    ../build/FullPSIBenchmark -b "fullhashx${n}.txt" -p "${p}" >>"$output_file"
  done
done
