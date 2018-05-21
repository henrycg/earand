#!/bin/bash
TIMEFORMAT='%3R'
SERVER='mbarara.stanford.edu'
#SERVER='bob.cs.yale.edu'
PORT=12346

echo "Running with $1 $2"
(./main $1 $2 $SERVER $PORT 0 0  2>&1 ) > /dev/null;
(./main $1 $2 $SERVER $PORT 0 0  2>&1 ) > /dev/null;
( for i in {1..8}
do 
( time ./main $1 $2 $SERVER $PORT 0 0  2>&1 | grep real )
done
) | while read one two; do echo $two; done

