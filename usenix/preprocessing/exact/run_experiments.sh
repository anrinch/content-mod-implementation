#!/bin/bash

echo "starting experiments for $1 iterations with db size $2..."
echo "starting experiments for $1 iterations with db size $2..." >>$6
start_time=$(date +%s)
for i in $(seq 1 $1); do
  python3 ExactMatchTest.py $2 0.000001 $3 $4 $5
done
end_time=$(date +%s)

echo "experiments complete in $((end_time - start_time)) seconds; results written to $5"
echo "experiments complete in $((end_time - start_time)) seconds; results written to $5" >>$6
awk -F',' '{sum+=$2; count++} END {print "average auditor time preprocessing: " sum/count "seconds"}' $5 >>$6
awk -F',' '{sum+=$3; count++} END {print "average client time preprocessing: " sum/count "seconds"}' $5 >>$6
awk -F',' '{sum+=$4; count++} END {print "average server time preprocessing: " sum/count "seconds"}' $5 >>$6
awk -F',' '{sum+=$5; count++} END {print "client query time: " sum/count "seconds"}' $5 >>$6
awk -F',' '{sum+=$6; count++} END {print "server query time: " sum/count "seconds"}' $5 >>$6
#awk -F',' 'BEGIN { max_value = 0 } NR > 1 { if ($7 > max_value) { max_value = $7 } } END { print "Maximum false positives observed: " max_value }' $5 >> $6
#awk -F',' 'BEGIN { count = 0 } NR > 1 {if ($8 != 0) count++} END {print "number of queries with false positives: " count}' $5 >> $6
awk -F',' '{sum+=$9; count++} END {print "client storage cost: " sum/count "MB"}' $5 >>$6
awk -F',' '{sum+=$10; count++} END {print "communication: " sum/count "KB"}' $5 >>$6
echo >>$6
echo >>$6

