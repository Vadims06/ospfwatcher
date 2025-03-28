if [ ! -d "watcher" ]; then
  mkdir watcher
fi
if [ ! -f watcher/watcher.log ]; then
  touch watcher/watcher.log
fi
# reset the log file to a clean slate
truncate -s0 watcher/watcher.log
sudo chown systemd-network:systemd-journal watcher/watcher.log
is_exist=$(brctl show br-dr)
if [[ -z "$is_exist" ]]; then
  sudo brctl addbr br-dr && \
  sudo ip link set up dev br-dr
fi