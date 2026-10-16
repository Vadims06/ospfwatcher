import pathlib

DAEMONS_PATH = pathlib.Path(__file__).resolve().parents[1] / "watcher" / "watcher-template" / "router" / "daemons"


def test_zebra_options():
    options = dict(line.split("=", 1) for line in DAEMONS_PATH.read_text().splitlines()
                   if "=" in line and not line.startswith("#"))
    # -n (VRF as netns) makes zebra of FRR 10.8 exit, leaving the watcher with Router ID 0.0.0.0
    assert options["zebra_options"] == '" -s 90000000 --daemon -A 127.0.0.1"'
