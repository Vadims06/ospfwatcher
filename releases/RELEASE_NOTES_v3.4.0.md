# OSPF Watcher Release Notes v3.4.0

## Changes

**Install from Topolograph**
Topolograph Enterprise's Watchers page now installs a watcher in GRE or BGP-LS mode. It
gives a `configure.sh` that checks the host, builds every watcher of the checkout with
`client.py --action add_watcher --answers`, and starts `topolograph-ospfwatcher.service`, which
redeploys the watchers at boot and starts Fluent Bit.
* Each watcher sends its events with its own token.
* Images are pinned to the checkout's `VERSION`; `REGISTRY_PREFIX` points them at a mirror.
* The interactive `client.py` dialog is unchanged.

**Listen-only filter rewritten: XDP replaced by tc-BPF on `gre1` egress**
The old filter inspected packets on the host end of the veth pair and let some
foreign prefixes through. The new filter runs on the egress of `gre1` inside the
watcher's network namespace and passes an LS Update only if every LSA is the
watcher's own Router LSA with the tunnel network. Drops are counted per reason.
The filter node no longer needs host networking.

**Renamed**
* Image `vadims06/ospf-filter-xdp` is now `vadims06/ospf-filter`.
* `client.py --action enable_xdp` / `disable_xdp` are now `enable_filter` / `disable_filter`.
* The `--answers` key `enable_xdp` is now `is_filter_enabled`.
* The prompt "Enable XDP?" is now "Enable announcement filter?".

**Fail closed, off by default**
The filter is off by default. With it on, the filter node brings `gre1` up after
attaching, so if it cannot attach there is no adjacency (fix the cause or run
`--action disable_filter`). It needs kernel 5.4 or newer; tested on 5.15.

**Known limit**
The watcher forwards no LSAs of other routers, so a network device that rebooted
cannot get them from the watcher.

## Upgrade

A watcher installed by hand moves to the Topolograph install as described in the README, *Moving a watcher installed by hand*.

1. Pull the repository and the `vadims06/ospf-filter` image.
2. For a watcher with the filter, run `client.py --action enable_filter --watcher_num <num>` and re-create its lab. This also pins `ospf router-id` in its FRR config.
