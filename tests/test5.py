import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))
from Helper import *

lsu_obj = LSU()
lsa_obj = LSA(lsu_obj)
lsa_obj.age_sec = 89
lsa_obj.adv_router_id = '10.1.1.2'
lsa_obj.link_state_id = '10.1.1.2'

ospf_RID_to_stub_net = {lsa_obj.adv_router_id: [
    {
        'subnet': '10.1.1.2/32', 
        'cost': 10, 
        'area': 1
    }, 
    {
        'subnet': '192.1.210.0/24', 
        'cost': 1, 
        'area': 1
    }
]}

graph_obj = Graph({}, {}, ospf_RID_to_stub_net, {}, {})

tmp_router_lsa_ll = [
    {
        'link_id': '10.1.1.2', 
        'link_data': '255.255.255.255', 
        'lsa_type': 3, 
        'metric': 20
    },
    {
        'link_id': '192.1.211.0', 
        'link_data': '255.255.255.0', 
        'lsa_type': 3, 
        'metric': 1
    }
]
for tmp_router_lsa in tmp_router_lsa_ll:
    STUBLSA(lsa_obj, tmp_router_lsa)

newStubNetworkSet, oldStubNetworkSet, changedMetricStubNetworkSet = graph_obj.doGetNewOldDiffStub(lsu_obj)
assert newStubNetworkSet == {'192.1.211.0/24'}, 'new Stub network detection error'
assert oldStubNetworkSet == {'192.1.210.0/24'}, 'old Stub network detection error'
assert changedMetricStubNetworkSet == {'10.1.1.2/32'}, 'change metric Stub network detection error'