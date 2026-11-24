# OSPF Watcher Release Notes v4.1.1

## Fixes

* Installation no longer fails when another Docker network overlaps `172.20.20.0/24`: each watcher gets its own management network with a free subnet.
* The watcher image connects to Topolograph over HTTPS.
* A route or router that comes back after it was withdrawn is reported at once, not with the next refresh of its LSA up to 30 minutes later.

## Upgrade
Run `configure.sh` again with the command from the watcher page. Every watcher restarts once.
