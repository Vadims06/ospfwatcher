import pathlib
import re
import sys
import types

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
pytest.importorskip("jinja2")
pytest.importorskip("ruamel.yaml")


def get_gre_rules(monkeypatch, watcher_num, router_ip):
    """Rules of one GRE watcher as its topology records them."""
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    # diagnostic needs scapy and netns, which only the watcher image has
    monkeypatch.setitem(sys.modules, "diagnostic", types.ModuleType("diagnostic"))
    import client
    watcher = client.WATCHER_CONFIG(watcher_num)
    watcher.gre_tunnel_network_device_ip = router_ip
    watcher.host_interface_device_ip = "192.168.0.140"
    watcher.gre_tunnel_number = watcher_num
    watcher.gre_tunnel_ip_w_mask_watcher = f"10.99.{watcher_num}.2/30"
    watcher.host_veth = f"ospf{watcher_num}-gre{watcher_num}"
    return [match["rule"] for command in watcher.exec_cmds() for match in [client.GRE_RULE_RE.search(command)] if match]


def test_gre_rules_of_two_watchers_never_coincide(monkeypatch):
    # The same router behind two hosts gives identical FORWARD rules, so only the comment tells their owner
    first = get_gre_rules(monkeypatch, 1, "172.31.50.2")
    second = get_gre_rules(monkeypatch, 2, "172.31.50.2")

    assert len(first) == 4
    assert not set(first) & set(second)
    assert all(re.search(r"--comment topolograph-ospfwatcher-watcher1-gre1-ospf\b", rule) for rule in first)
