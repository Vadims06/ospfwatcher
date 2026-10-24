import pathlib
import re
import shutil
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


def build_from_answers(monkeypatch, tmp_path, is_filter_enabled):
    """Watcher folder of a GRE watcher built the way configure.sh builds it."""
    shutil.copytree(REPO_ROOT / "watcher" / "watcher-template", tmp_path / "watcher" / "watcher-template")
    shutil.copy(REPO_ROOT / "VERSION", tmp_path / "VERSION")
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    monkeypatch.setitem(sys.modules, "diagnostic", types.ModuleType("diagnostic"))
    import client
    config = {
        "watcher_id": "id-1", "name": "w1", "connection_mode": "gre",
        "answers": {
            "gre_tunnel_network_device_ip": "172.31.50.2", "gre_tunnel_ip_w_mask_network_device": "10.10.25.32/24",
            "gre_tunnel_ip_w_mask_watcher": "10.10.25.33/24", "gre_tunnel_number": "1025", "ospf_area_num": "0",
            "host_interface_device_ip": "192.168.0.140", "organisation_name": "org",
            "is_filter_enabled": str(is_filter_enabled).lower(),
        },
        "server": {"watcher_name": "w1", "topolograph_host": "t.example", "topolograph_port": "443",
                   "topolograph_tls": "on", "watcher_token": "tok"},
    }
    client.WATCHER_CONFIG(1).add_watcher_from_answers(config)
    folder = tmp_path / "watcher" / "watcher1-gre1025-ospf"
    return client.WATCHER_CONFIG(1).get_existed_configs()[folder.name], (folder / "router" / "frr.conf").read_text()


def test_filter_node_runs_in_the_router_namespace_with_tunnel_settings(monkeypatch, tmp_path):
    config, frr_conf = build_from_answers(monkeypatch, tmp_path, True)
    node = config["topology"]["nodes"]["receive_only_filter"]

    assert node["image"].endswith("ospf-filter:v1")
    assert node["network-mode"] == "container:router"
    assert dict(node["env"]) == {"ROUTER_ID": "10.10.25.33", "TUNNEL_NETWORK": "10.10.25.0", "TUNNEL_PREFIX_LEN": "24"}
    assert "cap-add" not in node
    assert "ospf router-id 10.10.25.33" in frr_conf
    assert "h2" not in config["topology"]["nodes"]
    assert [dict(item) for item in config["topology"]["nodes"]["ospf-watcher"]["stages"]["create"]["wait-for"]] == [
        {"node": "receive_only_filter", "stage": "exit"}]


def test_filter_node_is_absent_when_the_filter_is_off(monkeypatch, tmp_path):
    config, _ = build_from_answers(monkeypatch, tmp_path, False)

    assert "receive_only_filter" not in config["topology"]["nodes"]
    assert [dict(item) for item in config["topology"]["nodes"]["h2"]["stages"]["create"]["wait-for"]] == [
        {"node": "h1", "stage": "configure"}]
    assert [dict(item) for item in config["topology"]["nodes"]["ospf-watcher"]["stages"]["create"]["wait-for"]] == [
        {"node": "h2", "stage": "create"}]
