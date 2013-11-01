#!/bin/bash
TIMEFORMAT='%3R'
echo "Running with $1"
( for i in {1..8}
do 
( time ./main rsa $1 localhost $2 0 0  2>&1 | grep user )
done
) | while read one two; do echo $two; done

