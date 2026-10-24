# OSPF Watcher Release Notes v4.0.0

**The watcher is rewritten in Rust**
One small binary with no Python. Events and their format stay the same.

**Install from Topolograph**
The Watchers page of Topolograph Enterprise gives one command that installs and starts a watcher in GRE or BGP-LS mode. Without Topolograph, write an answers file, see [docs/exporters.md](../docs/exporters.md).

**Built-in diagnostic**
`sudo onboarding/diagnostic.sh <num>` checks the GRE adjacency with the network device and prints the command that fixes what it finds.

**Announcement filter**
tc-BPF replaces XDP. It is off by default; turn it on with `is_filter_enabled`. See [Listen-only mode](../README.md#listen-only-mode-announcement-filter-in-action).

## Upgrade
Run `configure.sh` again with the command from the watcher page. Every watcher restarts once. A watcher installed by hand: see *Moving a watcher installed by hand* in the README.
