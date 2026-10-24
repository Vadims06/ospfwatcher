"""Runs crafted gre1-egress packets through the compiled filter with bpftool prog run."""
import json
import os
import struct
import subprocess
import sys

from scapy.all import IP, UDP, Raw, raw
from scapy.contrib.ospf import (OSPF_DBDesc, OSPF_Hdr, OSPF_Hello, OSPF_Link, OSPF_LSA_Hdr,
                                OSPF_LSAck, OSPF_LSUpd, OSPF_Network_LSA, OSPF_Router_LSA)

WATCHER = "10.10.25.33"
DEVICE = "10.10.25.32"
OTHER_ROUTER = "10.10.10.9"
TUNNEL_NET = "10.10.25.0"
TUNNEL_MASK = "255.255.255.0"
PASS, DROP = 0, 2  # TC_ACT_OK, TC_ACT_SHOT
REASONS = ["MALFORMED", "FRAGMENT", "LSA_COUNT", "LSA_TYPE", "LSA_ORIGIN", "LSA_FLAGS",
           "LSA_LENGTH", "LINK_TYPE", "FOREIGN_STUB", "P2P_COUNT"]


def router_lsa(links, adv=WATCHER, flags=0, lsa_id=None):
    return OSPF_Router_LSA(id=lsa_id or adv, adrouter=adv, seq=0x80000002, flags=flags, linklist=links)


P2P = OSPF_Link(type=1, id=DEVICE, data=WATCHER, metric=10)
STUB = OSPF_Link(type=3, id=TUNNEL_NET, data=TUNNEL_MASK, metric=10)
FOREIGN_STUB = OSPF_Link(type=3, id="8.8.8.8", data="255.255.255.255", metric=1)
TRANSIT = OSPF_Link(type=2, id=DEVICE, data=WATCHER, metric=10)
VIRTUAL = OSPF_Link(type=4, id=DEVICE, data=WATCHER, metric=10)


def ospf_packet(body, **ip_fields):
    return IP(src=WATCHER, dst="224.0.0.5", proto=89, **ip_fields) / OSPF_Hdr(src=WATCHER, area="0.0.0.0") / body


def lsu(lsas, **ip_fields):
    return ospf_packet(OSPF_LSUpd(lsalist=lsas), **ip_fields)


def with_md5_trailer(packet, trailer_first_bytes):
    """IP length covers the digest, the OSPF length does not."""
    ospf_bytes = bytearray(raw(packet))
    trailer = trailer_first_bytes + bytes(16 - len(trailer_first_bytes))
    ospf_bytes[2:4] = struct.pack(">H", len(ospf_bytes) + 16)
    return bytes(ospf_bytes) + trailer


def truncated(packet, cut_bytes):
    return raw(packet)[:-cut_bytes]


def lsu_with_num_lsas(num_lsas):
    data = bytearray(raw(lsu([router_lsa([P2P, STUB])])))
    data[44:48] = struct.pack(">I", num_lsas)
    return bytes(data)


# name, packet bytes, expected verdict, expected drop reason
CASES = [
    ("own Router LSA: P2P + tunnel stub", raw(lsu([router_lsa([P2P, STUB])])), PASS, None),
    ("own Router LSA: stub only, adjacency not yet Full", raw(lsu([router_lsa([STUB])])), PASS, None),
    ("stub replaced by 8.8.8.8/32", raw(lsu([router_lsa([P2P, FOREIGN_STUB])])), DROP, "FOREIGN_STUB"),
    ("third link 8.8.8.8/32", raw(lsu([router_lsa([P2P, STUB, FOREIGN_STUB])])), DROP, "FOREIGN_STUB"),
    ("third link 8.8.8.8/32, IP header with options (ihl 6)",
     raw(lsu([router_lsa([P2P, STUB, FOREIGN_STUB])], options=[b"\x01\x01\x01\x01"])), DROP, "FOREIGN_STUB"),
    ("own LSA with MD5 trailer starting with byte 2", with_md5_trailer(lsu([router_lsa([P2P, STUB])]), b"\x00" * 8 + b"\x02"), PASS, None),
    ("another router's Router LSA", raw(lsu([router_lsa([P2P, STUB], adv=OTHER_ROUTER)])), DROP, "LSA_ORIGIN"),
    ("own advertising router, foreign link state id", raw(lsu([router_lsa([P2P, STUB], lsa_id=OTHER_ROUTER)])), DROP, "LSA_ORIGIN"),
    ("own LSA with ASBR (E) bit", raw(lsu([router_lsa([P2P, STUB], flags=2)])), DROP, "LSA_FLAGS"),
    ("own LSA with ABR (B) bit", raw(lsu([router_lsa([P2P, STUB], flags=1)])), DROP, "LSA_FLAGS"),
    ("transit link", raw(lsu([router_lsa([TRANSIT, STUB])])), DROP, "LINK_TYPE"),
    ("virtual link", raw(lsu([router_lsa([VIRTUAL, STUB])])), DROP, "LINK_TYPE"),
    ("two point-to-point links", raw(lsu([router_lsa([P2P, P2P, STUB])])), DROP, "P2P_COUNT"),
    ("own LSA followed by another router's LSA",
     raw(lsu([router_lsa([P2P, STUB]), router_lsa([P2P, STUB], adv=OTHER_ROUTER)])), DROP, "LSA_ORIGIN"),
    ("network LSA", raw(lsu([OSPF_Network_LSA(id=WATCHER, adrouter=WATCHER, mask=TUNNEL_MASK, routerlist=[WATCHER])])), DROP, "LSA_TYPE"),
    ("num_lsas 0", lsu_with_num_lsas(0), DROP, "LSA_COUNT"),
    ("num_lsas 1000", lsu_with_num_lsas(1000), DROP, "LSA_COUNT"),
    ("LSU cut in the middle of a link", truncated(lsu([router_lsa([P2P, STUB])]), 8), DROP, "MALFORMED"),
    ("LSU fragment", raw(lsu([router_lsa([P2P, STUB])], flags="MF")), DROP, "FRAGMENT"),
    ("Hello", raw(ospf_packet(OSPF_Hello(mask=TUNNEL_MASK))), PASS, None),
    ("LS Ack", raw(ospf_packet(OSPF_LSAck(lsaheaders=[OSPF_LSA_Hdr(type=1, id=OTHER_ROUTER, adrouter=OTHER_ROUTER)]))), PASS, None),
    ("DD with two LSA headers (resync)",
     raw(ospf_packet(OSPF_DBDesc(ddseq=5, dbdescr=0, lsaheaders=[
         OSPF_LSA_Hdr(type=1, id=WATCHER, adrouter=WATCHER),
         OSPF_LSA_Hdr(type=1, id=OTHER_ROUTER, adrouter=OTHER_ROUTER)]))), PASS, None),
    ("non-OSPF UDP", raw(IP(src=WATCHER, dst=DEVICE) / UDP() / Raw(b"x" * 40)), PASS, None),
]


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def attach_with_entrypoint():
    """Attaches with the production entrypoint and tc, then returns the program and map ids."""
    run(["ip", "link", "add", "filtertest0", "type", "veth", "peer", "name", "filtertest1"])
    environment = {"FILTER_INTERFACE": "filtertest0", "ROUTER_ID": WATCHER, "TUNNEL_NET": TUNNEL_NET,
                   "TUNNEL_MASK": TUNNEL_MASK, "PATH": os.environ["PATH"]}
    subprocess.run(["/attach_filter.sh"], check=True, capture_output=True, env=environment)
    prog_id = int(run(["tc", "filter", "show", "dev", "filtertest0", "egress"]).split(" id ")[1].split()[0])
    map_id = json.loads(run(["bpftool", "-j", "prog", "show", "id", str(prog_id)]))["map_ids"][0]
    return prog_id, map_id


def read_counters(map_id):
    dump = json.loads(run(["bpftool", "-j", "map", "dump", "id", str(map_id)]))
    return [entry["formatted"]["value"] if "formatted" in entry else entry["value"] for entry in dump]


def main():
    prog_id, map_id = attach_with_entrypoint()
    ethernet_header = bytes(6) + bytes(6) + b"\x08\x00"  # test run requires L2; the filter reads from the IP header, as on gre1 egress
    failures = 0
    for name, packet, expected_verdict, expected_reason in CASES:
        before = read_counters(map_id)
        with open("/tmp/case.bin", "wb") as case_file:
            case_file.write(ethernet_header + packet)
        output = run(["bpftool", "prog", "run", "id", str(prog_id), "data_in", "/tmp/case.bin", "repeat", "1"])
        verdict = int(output.split("Return value:")[1].split(",")[0])
        after = read_counters(map_id)
        bumped = [REASONS[index] for index in range(len(REASONS)) if after[index] != before[index]]
        expected_bumped = [expected_reason] if expected_reason else []
        status = "ok   " if (verdict, bumped) == (expected_verdict, expected_bumped) else "WRONG"
        failures += status == "WRONG"
        print(f"{status} {'PASS' if verdict == PASS else 'DROP'} {','.join(bumped) or '-':13} {name}")
    sys.exit(1 if failures else 0)


main()
