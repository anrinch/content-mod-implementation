#!/bin/bash

echo "starting experiments for $1 iterations with db size $2 and $4 partitions ..." 
echo "starting experiments for $1 iterations with db size $2 and $4 partitions ..."  >> $7
start_time=$(date +%s) 
for i in $(seq 1 $1); do 
python3 ApproximateMatchTest.py $2 $3 $4 $5 $6
done
end_time=$(date +%s)

echo "experiments complete in $((end_time - start_time)) seconds; results written to $6" 
echo "experiments complete in $((end_time - start_time)) seconds; results written to $6" >> $7
awk -F',' '{sum+=$2; count++} END {print "average server setup time: " sum/count "seconds"}' $6 >> $7
awk -F',' '{sum+=$3; count++} END {print "client query time: " sum/count "seconds"}' $6 >> $7
awk -F',' '{sum+=$4; count++} END {print "communication: " sum/count " KB"}' $6 >> $7
echo >> $7
echo >> $7