import os
import pathlib
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WATCHER = "ospfwatcher"
NAT_RULES = f"""-P PREROUTING ACCEPT
-A PREROUTING -s 10.10.10.1/32 -d 192.168.0.140/32 -p gre -m comment --comment topolograph-{WATCHER} -j DNAT --to-destination 169.254.1.2
-A POSTROUTING -s 169.254.1.2/32 -d 10.10.10.1/32 -p gre -m comment --comment topolograph-{WATCHER} -j SNAT --to-source 192.168.0.140
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
"""
FAKE_COMMANDS = {
    "iptables": 'echo "$*" >> "$LOG_DIR/iptables"; [ "$*" = "-w -t nat -S" ] && cat "$LOG_DIR/nat_rules"; exit 0',
    # Exits 1 like the real one when no flow matches
    "conntrack": 'echo "$*" >> "$LOG_DIR/conntrack"; exit 1',
    "containerlab": "exit 0",
    "docker": "exit 0",
}


def test_stop_removes_gre_flows(tmp_path):
    (tmp_path / "onboarding").mkdir()
    shutil.copy(REPO_ROOT / "onboarding" / "stop.sh", tmp_path / "onboarding" / "stop.sh")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    for name, body in FAKE_COMMANDS.items():
        (bin_path / name).write_text(f"#!/bin/sh\n{body}\n")
        (bin_path / name).chmod(0o755)
    (tmp_path / "nat_rules").write_text(NAT_RULES)
    environment = {**os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "LOG_DIR": str(tmp_path)}

    result = subprocess.run(["bash", str(tmp_path / "onboarding" / "stop.sh")], env=environment)

    assert result.returncode == 0
    assert (tmp_path / "conntrack").read_text().splitlines() == [
        "-D -p gre -s 10.10.10.1 -d 192.168.0.140",
        "-D -p gre -s 169.254.1.2 -d 10.10.10.1",
    ]
    assert (tmp_path / "iptables").read_text().splitlines() == [
        "-w -t nat -S",
        f"-w -t nat -D PREROUTING -s 10.10.10.1/32 -d 192.168.0.140/32 -p gre -m comment --comment topolograph-{WATCHER} -j DNAT --to-destination 169.254.1.2",
        f"-w -t nat -D POSTROUTING -s 169.254.1.2/32 -d 10.10.10.1/32 -p gre -m comment --comment topolograph-{WATCHER} -j SNAT --to-source 192.168.0.140",
        "-w -t filter -S",
    ]
