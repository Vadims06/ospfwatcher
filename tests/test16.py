import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from Helper import *
import pytest


p2pOwnRidToOwnIpAddressDdDdMap = {'10.1.1.4': {'172.17.0.1': 1200, '192.16.0.1': 10}}
p2pOwnIpAddressWithRemoteNeighborRidMap = {'172.17.0.1': '192.168.100.100', '192.16.0.1': '192.168.100.101'}
graph_obj = Graph(p2pOwnRidToOwnIpAddressDdDdMap, p2pOwnIpAddressWithRemoteNeighborRidMap, {}, {}, {})

lsu_obj = LSU()

lsa_obj = LSA(lsu_obj)
lsa_obj.age_sec = 89
lsa_obj.adv_router_id = '10.1.1.4'
lsa_obj.link_state_id = '10.1.1.4'
tmp_router_lsa_ll = [
    {
        'link_id': '192.168.100.100',
        'link_data': '172.17.0.1',
        'lsa_type': 1,
        'metric': 1000
    },
    {
        'link_id': '192.168.100.102',
        'link_data': '172.18.0.1',
        'lsa_type': 1,
        'metric': 1000
    }
]
for tmp_router_lsa in tmp_router_lsa_ll:
    p2p_obj = P2PLSA(lsa_obj, tmp_router_lsa)

newP2pOwnIpAddressSet, oldP2pOwnIpAddressSet, changedP2pOwnIpAddressSet = graph_obj.doGetNewOldDiffP2p(lsu_obj)
assert newP2pOwnIpAddressSet == {'172.18.0.1'}, 'new p2p neighbor detection error'
assert oldP2pOwnIpAddressSet == {'192.16.0.1'}, 'old p2p neighbor detection error'
assert changedP2pOwnIpAddressSet == {'172.17.0.1'}, 'change metric p2p neighbor detection error'