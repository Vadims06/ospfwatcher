# OSPF Watcher Release Notes v4.1.0

**Macvlan mode**
A third connection mode next to GRE and BGP-LS: the watcher forms an OSPF adjacency with a router on the same L2 segment, over a physical or VLAN interface of the host. No tunnel and no iptables rules. The announcement filter is always on in this mode. See [Macvlan mode](../README.md#macvlan-mode) for the limits.

**Announcement filter v2.0.0**
The filter works on Ethernet as well as GRE, and drops any OSPF packet it cannot read.

## Upgrade
Run `configure.sh` again with the command from the watcher page. Every watcher restarts once.
