import os
import pytest
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


@pytest.mark.parametrize("check_code, delete_code, exit_code, deleted", [
    (0, 0, 0, True),
    # The rule is there and cannot be removed: the old topology would keep its NAT
    (0, 1, 1, True),
    # An absent rule is nothing to remove
    (1, 1, 0, False),
])
def test_stop_reports_a_rule_it_cannot_delete(tmp_path, check_code, delete_code, exit_code, deleted):
    (tmp_path / "onboarding").mkdir()
    shutil.copy(REPO_ROOT / "onboarding" / "stop.sh", tmp_path / "onboarding" / "stop.sh")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    fakes = {"iptables": 'echo "$*" >> "$LOG_DIR/iptables"; case "$*" in *" -C "*) exit $CHECK_CODE;; *" -D "*) exit $DELETE_CODE;; esac; exit 0',
             "conntrack": "exit 1", "containerlab": "exit 0", "docker": "exit 0"}
    for name, fake_body in fakes.items():
        (bin_path / name).write_text(f"#!/bin/sh\n{fake_body}\n")
        (bin_path / name).chmod(0o755)
    config = tmp_path / "config.yml"
    comment = f"-m comment --comment topolograph-{WATCHER}"
    config.write_text(
        f"""name: watcher1-gre1-ospf
- bash -c 'RULE="-t filter -p gre {comment} -s 10.10.10.1 -j ACCEPT"; sudo iptables -C FORWARD $$RULE &> /dev/null && echo exists || sudo iptables -A FORWARD $$RULE'
""")
    environment = {**os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "LOG_DIR": str(tmp_path),
                   "CHECK_CODE": str(check_code), "DELETE_CODE": str(delete_code)}

    result = subprocess.run(["bash", str(tmp_path / "onboarding" / "stop.sh"), str(config)], env=environment)

    assert result.returncode == exit_code
    logged = (tmp_path / "iptables").read_text()
    assert (" -D FORWARD " in logged) == deleted


@pytest.mark.parametrize("has_containers", [True, False])
def test_stop_of_one_watcher_leaves_the_other(tmp_path, has_containers):
    (tmp_path / "onboarding").mkdir()
    shutil.copy(REPO_ROOT / "onboarding" / "stop.sh", tmp_path / "onboarding" / "stop.sh")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    fakes = {**FAKE_COMMANDS,
             "containerlab": 'echo "$*" >> "$LOG_DIR/containerlab"; exit 0',
             # A crashed lab leaves exited containers, which docker ps -a still lists
             "docker": 'echo "$*" >> "$LOG_DIR/docker"; [ -n "$CONTAINERS" ] && echo abc123; exit 0'}
    for name, fake_body in fakes.items():
        (bin_path / name).write_text(f"#!/bin/sh\n{fake_body}\n")
        (bin_path / name).chmod(0o755)
    config = tmp_path / "config.yml"
    comment = f"-m comment --comment topolograph-{WATCHER}"
    config.write_text(
        f"""name: watcher1-gre1-ospf
- bash -c 'RULE="-t nat -p gre {comment} -s 169.254.1.2 -d 10.10.10.1 -j SNAT --to-source 192.168.0.140"; sudo iptables -C POSTROUTING $$RULE &> /dev/null && echo exists || sudo iptables -A POSTROUTING $$RULE'
- bash -c 'RULE="-t nat -p gre {comment} -s 10.10.10.1 -d 192.168.0.140 -j DNAT --to-destination 169.254.1.2"; sudo iptables -C PREROUTING $$RULE &> /dev/null && echo exists || sudo iptables -A PREROUTING $$RULE'
- bash -c 'RULE="-t filter -p gre {comment} -s 10.10.10.1 -j ACCEPT"; sudo iptables -C FORWARD $$RULE &> /dev/null && echo exists || sudo iptables -A FORWARD $$RULE'
""")
    environment = {**os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "LOG_DIR": str(tmp_path),
                   "CONTAINERS": "1" if has_containers else ""}

    result = subprocess.run(["bash", str(tmp_path / "onboarding" / "stop.sh"), str(config)], env=environment)

    assert result.returncode == 0
    destroyed = (tmp_path / "containerlab").exists()
    assert destroyed == has_containers
    assert (tmp_path / "conntrack").read_text().splitlines() == [
        "-D -p gre -s 169.254.1.2 -d 10.10.10.1",
        "-D -p gre -s 10.10.10.1 -d 192.168.0.140",
    ]
    # Only this watcher's own rules go: no listing of the table, so a sibling's rules are never read
    rules = [
        f"POSTROUTING -t nat -p gre {comment} -s 169.254.1.2 -d 10.10.10.1 -j SNAT --to-source 192.168.0.140",
        f"PREROUTING -t nat -p gre {comment} -s 10.10.10.1 -d 192.168.0.140 -j DNAT --to-destination 169.254.1.2",
        f"FORWARD -t filter -p gre {comment} -s 10.10.10.1 -j ACCEPT",
    ]
    assert (tmp_path / "iptables").read_text().splitlines() == [
        line for rule in rules for line in (f"-w -C {rule}", f"-w -D {rule}")]


def test_stop_of_a_macvlan_watcher_only_destroys_its_lab(tmp_path):
    (tmp_path / "onboarding").mkdir()
    shutil.copy(REPO_ROOT / "onboarding" / "stop.sh", tmp_path / "onboarding" / "stop.sh")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    fakes = {**FAKE_COMMANDS,
             "containerlab": 'echo "$*" >> "$LOG_DIR/containerlab"; exit 0',
             "docker": "echo abc123; exit 0",
             "ip": 'echo "$*" >> "$LOG_DIR/ip"; exit 0'}
    for name, fake_body in fakes.items():
        (bin_path / name).write_text(f"#!/bin/sh\n{fake_body}\n")
        (bin_path / name).chmod(0o755)
    config = tmp_path / "config.yml"
    config.write_text("name: watcher1-mv-ens192-100-ospf\n")
    environment = {**os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "LOG_DIR": str(tmp_path)}

    result = subprocess.run(["bash", str(tmp_path / "onboarding" / "stop.sh"), str(config)], env=environment)

    assert result.returncode == 0
    assert (tmp_path / "containerlab").read_text().splitlines() == [f"destroy -t {config}"]
    # The parent interface belongs to the host: nothing may delete it, and no GRE flow exists to clean
    assert not (tmp_path / "ip").exists() and not (tmp_path / "iptables").exists() and not (tmp_path / "conntrack").exists()
