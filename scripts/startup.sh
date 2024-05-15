#!/bin/bash
cd /ros2_ws
colcon build --packages-up-to saft_pipeline
source /ros2_ws/install/setup.sh
ros2 run saft_pipeline saft_pipeline_node
# exec "$@"