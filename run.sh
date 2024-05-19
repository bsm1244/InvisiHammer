for i in {0..1000}
do
  sudo numactl -C 0 -m 0 ./templating 4 >> log 2>&1
done