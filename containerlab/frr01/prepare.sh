sudo chown systemd-network:systemd-journal watcher/watcher.log
is_exist=$(brctl show br-dr)
if [[ -z "$is_exist" ]]; then
  sudo brctl addbr br-dr && \
  sudo ip link set up dev br-dr
fi