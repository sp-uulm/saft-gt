#!/bin/bash

stages=(      64  512  2048 4096 8192)
# stages=(      2   4   8  16  32  64 128 256 512 1024 2048 4096 8192)
iterations=(  10  100   100  100  100)
# iterations=(100 100 100 100 100  10 100 100 100  100  100  100  100)
sleeps=(      300  30    20    3   40)
# sleeps=(      3   1   1   4   4 300   1  25  10    3   20    3    1)

for i in ${!stages[@]}; do
  stage=${stages[$i]}
  runs=${iterations[$i]}
  pause=${sleeps[$i]}

  echo "==========================================="
  echo "stage: ${stage}"
  echo "number of runs of this stage: ${runs}"
  echo "waiting time between two runs: ${pause} s"

  if [[ $stage -eq 8 ]]
  then
  	echo "copy!"
  	cp ros2_ws/src/models/ros.dataflow.orig ros2_ws/src/models/ros.dataflow
  fi
  
  for j in $(seq 1 1 $runs)
  do
  	echo -n "stage ${stage}, run ${j}: "
  	./run_stage.sh $stage
  	sleep $pause
  done
done