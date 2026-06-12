#!/bin/bash

### clean up log files

if [ -e "experiments.log" ]; then
  rm "experiments.log"
  touch experiments.log
fi

### small test
test_array=($((2 ** 14)))

### full test
#test_array=($((2**14)) $((2**15)) $((2**16)) $((2**17)) $((2**18)) $((2**19)) $((2**20)))

for dbSize in "${test_array[@]}"; do
  if [ -e "hashes_in.txt" ]; then
    rm "hashes_in.txt"
  fi
  python3 HashGenerator.py "$dbSize"
  mv hashes.txt hashes_in.txt
  if [ -e "hashes_test.txt" ]; then
    rm "hashes_test.txt"
  fi
  python3 HashGenerator.py "$dbSize"
  mv hashes.txt hashes_test.txt
  ./run_experiments.sh $1 "$dbSize" "hashes_in.txt" "hashes_test.txt" "em_"$dbSize".log" "experiments.log"
  rm "hashes_in.txt" "hashes_test.txt" "em_"$dbSize".log"
done
