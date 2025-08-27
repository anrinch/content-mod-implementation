#!/bin/bash

### clean up log files

if [ -e "experiments.log" ]; then
  rm "experiments.log"
  touch experiments.log
fi

test_array=($((2 ** 10)))
proj_array=($((10)) $((20)) $((30)) $((40)))

for dbSize in "${test_array[@]}"; do
  for projNum in "${proj_array[@]}"; do
    if [ -e "temp/inFile.txt" ]; then
      rm "temp/inFile.txt"
    fi
    ./run_experiments.sh $1 "$dbSize" 256 "$projNum" 5 "fm_"$dbSize"_"$projNum".log" "experiments.log"
  done
done
