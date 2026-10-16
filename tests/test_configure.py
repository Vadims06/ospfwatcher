import os
import pathlib
import shutil
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
OLD = "watcher1-gre1-ospf"
RENAMED = "watcher1-gre2-ospf"
SIBLING = "watcher2-gre1-ospf"
SIBLING_RENAMED = "watcher2-gre3-ospf"
# Hands-off commands: only docker, containerlab, curl and the rebuild step do anything the test reads
FAKES = {
    "id": 'echo 0',
    "systemctl": "exit 0",
    "flock": "exit 0",
    "iptables": "exit 0",
    "conntrack": "exit 1",
    "curl": 'out=""; timed=""; while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift;; -w) timed=1;; esac; shift; done; '
            '[ "$CURL_FAILS" = 1 ] && exit 7; [ -z "$out" ] || echo "{}" > "$out"; [ -z "$timed" ] || echo 200',
    "containerlab": 'echo "$*" >> "$LOG_DIR/containerlab"; [ -z "$UNSTOPPABLE" ] || case "$*" in *destroy*"$UNSTOPPABLE"*) exit 1;; esac; exit 0',
    "docker": 'case "$*" in "run "*add_watcher*) eval "$REBUILD";; ps*label=containerlab=*) echo abc;; esac; exit 0',
}


def write_watcher(folder, name, watcher_id, with_marker=False):
    folder.mkdir(parents=True)
    (folder / "config.yml").write_text(
        f"name: {name}\ntopology:\n  defaults:\n    labels:\n      watcher_id: '{watcher_id}'\n")
    (folder / "fluent-bit.yaml").write_text(f"input of {name}\n")
    if with_marker:
        (folder / ".pending-stop").touch()


def run_configure(tmp_path, folders, rebuild="", unstoppable="", curl_fails=False):
    shutil.copy(REPO_ROOT / "configure.sh", tmp_path / "configure.sh")
    shutil.copytree(REPO_ROOT / "onboarding", tmp_path / "onboarding", dirs_exist_ok=True)
    (tmp_path / "VERSION").write_text("1.0\n")
    (tmp_path / ".env.template").write_text("REGISTRY_PREFIX=\n")
    (tmp_path / "watcher").mkdir()
    (tmp_path / "fluentbit" / "watchers").mkdir(parents=True)
    (tmp_path / "fluentbit" / "watchers" / f"{RENAMED}.yaml").write_text("stale\n")
    for name, (watcher_id, with_marker) in folders.items():
        write_watcher(tmp_path / "watcher" / name, name, watcher_id, with_marker)
        (tmp_path / "fluentbit" / "watchers" / f"{name}.yaml").write_text(f"input of {name}\n")
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    for name, body in FAKES.items():
        (bin_path / name).write_text(f"#!/bin/sh\n{body}\n")
        (bin_path / name).chmod(0o755)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                    "--allow-empty", "-m", "base"], check=True)
    environment = {**os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "LOG_DIR": str(tmp_path),
                   "REBUILD": rebuild, "UNSTOPPABLE": unstoppable, "CURL_FAILS": "1" if curl_fails else ""}
    return subprocess.run(["bash", str(tmp_path / "configure.sh"), "--url", "http://t", "--token", "x"],
                          env=environment, capture_output=True, text=True)


def get_logged(tmp_path):
    path = tmp_path / "containerlab"
    return path.read_text() if path.exists() else ""


def test_failed_stop_keeps_old_folder_and_deploys_no_replacement(tmp_path):
    id_old, id_sibling = "a" * 24, "b" * 24
    rebuild = (f"mv watcher/{OLD} watcher/{RENAMED}; mv watcher/{SIBLING} watcher/{SIBLING_RENAMED}")

    result = run_configure(tmp_path, {OLD: (id_old, False), SIBLING: (id_sibling, False)},
                           rebuild=rebuild, unstoppable="watcher1")

    assert result.returncode == 1
    assert OLD in result.stderr
    assert (tmp_path / "watcher" / OLD / ".pending-stop").exists()
    assert not (tmp_path / "watcher" / RENAMED).exists()
    logged = get_logged(tmp_path)
    assert f"deploy --reconfigure -t watcher/{RENAMED}/config.yml" not in logged
    assert f"deploy --reconfigure -t watcher/{OLD}/config.yml" not in logged
    assert f"deploy --reconfigure -t watcher/{SIBLING_RENAMED}/config.yml" in logged
    # Fluent Bit inputs are exactly the folders that exist now
    assert sorted(path.name for path in (tmp_path / "fluentbit" / "watchers").iterdir()) == [
        f"{OLD}.yaml", f"{SIBLING_RENAMED}.yaml"]


@pytest.mark.parametrize("unstoppable, exit_code, marker_left", [("", 1, False), ("watcher1", 1, True)])
def test_pending_stop_is_retried_first(tmp_path, unstoppable, exit_code, marker_left):
    result = run_configure(tmp_path, {OLD: ("a" * 24, True)}, unstoppable=unstoppable, curl_fails=True)

    assert result.returncode == exit_code
    assert f"destroy -t watcher/{OLD}/config.yml" in get_logged(tmp_path)
    assert (tmp_path / "watcher" / OLD / ".pending-stop").exists() == marker_left
    # A failed retry stops before the registration is even fetched
    assert ("Cannot reach Topolograph" in result.stderr) == (not marker_left)
    assert (OLD in result.stderr) == marker_left
