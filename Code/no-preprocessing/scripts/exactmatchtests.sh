#!/bin/bash

#echo "Signing block list..."
#../build/networked-aud1024 -b exact64.txt
#
#LOGFILE="server.log"
#
#rm -f "$LOGFILE"
#
#../build/grpc-test -r 1 -a 0.0.0.0:50051 -c ./config.json -b exact64.txt >"$LOGFILE" 2>&1 &
#SERVER_PID=$!
#
#(
#  while read -r line; do
#    echo "$line"
#    if [[ "$line" == *"server running @ 0.0.0.0:50051"* ]]; then
#      echo "Server is ready, starting client..."
#      ../build/grpc-test -r 0 -a 0.0.0.0:50051 -e "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" -p "test" -c ./config.json
#      break
#    fi
#  done
#) < <(tail -n 0 -f "$LOGFILE")
#
## Cleanup
#kill $SERVER_PID 2>/dev/null
#wait $SERVER_PID 2>/dev/null

# Usage: ./run.sh <blocklist-file>
BLOCKLIST_FILE=${1:-exact64.txt} # Default to exact64.txt if not given

echo "Using block list: $BLOCKLIST_FILE"
echo "Signing block list..."
../build/networked-aud1024 -b "$BLOCKLIST_FILE"

LOGFILE="server.log"

rm -f "$LOGFILE"

../build/grpc-test -r 1 -a 0.0.0.0:50051 -c ./config.json -b "$BLOCKLIST_FILE" >"$LOGFILE" 2>&1 &
SERVER_PID=$!

(
  while read -r line; do
    echo "$line"
    if [[ "$line" == *"server running @ 0.0.0.0:50051"* ]]; then
      echo "Server is ready, starting client..."
      ../build/grpc-test -r 0 -a 0.0.0.0:50051 \
        -e "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
        -p "test" \
        -c ./config.json
      break
    fi
  done
) < <(tail -n 0 -f "$LOGFILE")

# Cleanup
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null
