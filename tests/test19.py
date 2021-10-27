import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from Helper import *
import pytest

DrIpAddressToNeighborsRidSetMap = {'10.1.123.23': {'10.1.1.2', '10.1.123.23', '10.1.123.24'}}
# 10.1.123.23 is DR
OwnRidToOwnIpToDrIpAddressToMetricMap = {'10.1.123.24': {'10.1.123.24': {'10.1.123.23': 10}}, 
                                '10.1.123.23': {'10.1.123.23': {'10.1.123.23': 11}}, 
                                '10.1.1.2': {'10.1.123.1': {'10.1.123.23': 12}}}
graph_obj = Graph({}, {}, {}, DrIpAddressToNeighborsRidSetMap, OwnRidToOwnIpToDrIpAddressToMetricMap)

lsu_obj = LSU()


lsa_obj = LSA(lsu_obj)
lsa_obj.age_sec = 3
lsa_obj.adv_router_id = '10.1.1.2'
lsa_obj.link_state_id = '10.1.1.2'

tmp_router_lsa = {
'link_id': '10.1.1.2',
'link_data': '10.1.123.1',
'lsa_type': 2,
'metric': 10
}

lsa_obj.isNewMetricOrNewDr_check(tmp_router_lsa, graph_obj=graph_obj)

sample_test = {
    lsa_obj.link_state_id: {'10.1.1.2', '10.1.123.24'},
}
for lsa2_neighbor in sample_test.get(lsa_obj.link_state_id):
    lsa_obj.dr_neigh_add(lsa2_neighbor_rid=lsa2_neighbor)

newNeighbors, oldNeighbors = graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
assert newNeighbors == set(), 'new neighbor in transit network detection error'
assert oldNeighbors == {'10.1.123.23'}, 'old neighbor in transit network detection error'