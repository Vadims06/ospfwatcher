import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from Helper import *
import pytest

DrIpAddressToNeighborsRidSetMap = {'10.1.24.4': {'10.1.1.2', '10.1.1.4'}, '10.1.23.3': {'10.1.1.2', '10.1.1.3'}}
drIpAddressToMetricMap = {'10.1.24.4': 100, '10.1.23.3': 10}
graph_obj = Graph({}, {}, {}, DrIpAddressToNeighborsRidSetMap, drIpAddressToMetricMap)

lsu_obj = LSU()

sample_test = {
    '10.1.24.4': {'10.1.1.4'},
}
lsa_obj = LSA(lsu_obj)
lsa_obj.age_sec = 3600
lsa_obj.adv_router_id = '10.1.1.4'
lsa_obj.link_state_id = '10.1.24.4'

for lsa2_neighbor in sample_test.get(lsa_obj.link_state_id):
    lsa_obj.dr_neigh_add(lsa2_neighbor_rid=lsa2_neighbor)

newNeighbors, oldNeighbors = graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
assert newNeighbors == set(), 'new neighbor in transit network detection error'
assert oldNeighbors == {'10.1.1.2'}, 'old neighbor in transit network detection error'

sample_test = {
    '10.1.23.3': {'10.1.1.2', '10.1.1.3', '10.1.1.4'},
}
graph_obj = Graph({}, {}, {}, DrIpAddressToNeighborsRidSetMap, drIpAddressToMetricMap)
lsa_obj = LSA(lsu_obj)
lsa_obj.age_sec = 10
lsa_obj.adv_router_id = '10.1.1.3'
lsa_obj.link_state_id = '10.1.23.3'


for lsa2_neighbor in sample_test.get(lsa_obj.link_state_id):
    lsa_obj.dr_neigh_add(lsa2_neighbor_rid=lsa2_neighbor)

newNeighbors, oldNeighbors = graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
assert newNeighbors == {'10.1.1.4'}, 'new neighbor in transit network detection error'
assert oldNeighbors == set(), 'old neighbor in transit network detection error'