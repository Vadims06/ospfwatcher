import re
from collections import defaultdict
from Helper import *
import ipaddress, time

def follow(file):
    """ Yield each line from a file as they are written. """
    line = ''
    while True:
        tmp = file.readline()
        if tmp is not None:
            line += tmp
            if line.endswith("\n"):
                yield line
                line = ''
        else:
            time.sleep(0.1)


if __name__ == '__main__':
    # LSU. 2021/08/08 22:03:10 OSPF:   Type 4 (Link State Update)
    re_link_state_update = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Type\s+4\s+\(Link\s+State\s+Update\)')
    # LSU. LSA Header. 2021/08/21 15:44:39 OSPF:   LSA Header
    re_lsa_header = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+LSA Header')
    # LSU. LSA Header. 2021/08/12 18:30:24 OSPF:     LS age 3600
    re_lsa_age_sec = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+LS age\s*(?P<lsa_age_sec>\d+)')
    # LSU. LSA Header. 2021/08/12 18:30:24 OSPF:     Link State ID 10.1.1.2
    re_lsa_link_state_id = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Link State ID\s+(?P<link_state_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    # LSU. LSA Header. 2021/08/16 19:44:22 OSPF: Advertising Router 10.1.1.2
    re_adv_router = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s*Advertising Router\s*(?P<adv_router_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    # LSU. LSA1 Body. 2021/08/12 18:30:25 OSPF:   Router-LSA
    re_router_lsa_header = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Router-LSA')
    # LSU. LSA1 Body. 2021/08/12 18:30:25 OSPF: Link ID 10.1.1.3
    re_routerLsaLinkId = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Link ID\s+(?P<link_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    # LSU. LSA1 Body. 2021/08/12 18:30:25 OSPF: Link Data 255.255.255.255
    re_routerLsaLinkData = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Link Data\s+(?P<link_data>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    # LSU. LSA1 Body. 2021/08/12 18:30:25 OSPF: Type 3
    re_routerLsaType = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Type\s+(?P<lsa_type>\d)')
    # LSU. LSA1 Body. 2021/08/12 18:30:25 OSPF:     metric 1000
    re_routerLsaMetric = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+metric\s+(?P<metric>\d+)')

    # LSU. LSA2 Body. 2021/08/21 15:44:39 OSPF:   Network-LSA
    re_network_lsa_header = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Network-LSA')
    # LSU. LSA2 Body. 2021/08/21 15:44:39 OSPF:   Network Mask 255.255.255.0
    re_networkLsaNetworkMask = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Network Mask\s*(?P<network_mask>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    # LSU. LSA2 Body. 
    # 2021/08/21 15:44:39 OSPF:       Attached Router 10.1.1.4
    # 2021/08/21 15:44:39 OSPF:       Attached Router 10.1.1.2
    re_networkLsaNeighbor = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Attached Router\s*(?P<lsa2_neighbor>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    
    # End message
    # [-] 2021/08/12 18:30:25 OSPF: SPF: Scheduled in 13 msec
    re_spf = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+SPF:\s+Scheduled\s+in\s+\d+\s+msec')
    # 2021/08/12 18:30:24 OSPF: Link State Update received from [10.1.1.4] via [gre1:172.17.0.100]
    re_end_line = re.compile('(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) OSPF:\s+Link State Update received from')
    # Log string output
    hostDownLog_str = "host: {neighborName} {newStateUpDown}, detected by: {lsa_adv_router_id}"

    # variables
    ##LsuRouterLsaDetails = {}
    ##routerLsaDetails = {} # p2p, broadcast
    process_lsa_header = False
    process_router_lsa = False # when we met a Router lSA header - we know that next lines will be Router LSA details
    process_network_lsa = False
    graph_dd_dd = {} # include p2p, broadcast adjancency
    hostToDrIpAddressMap = {}
    DrIpAddressToNeighborsRidSetMap = {} # Topolograph Helpers - ospf_DR_and_neighs
    # FOR DEMO ONLY
    DrIpAddressToNeighborsRidSetMap = {'10.1.34.4': {'10.1.1.3', '10.1.1.4'}, '10.1.23.3': {'10.1.1.3', '10.1.1.2'}}
    hostToP2pMapFromGraph = defaultdict(dict)
    # Request Topology
    p2pOwnRidToOwnIpAddressDdDdMap = {}
    p2pOwnIpAddressWithRemoteNeighborRidMap = {}
    ospf_RID_to_stub_net = {}
    drIpAddressToMetricMap = {}
    # for demo
    test_num = 30
    if test_num == 5:
        ospf_RID_to_stub_net = {'10.1.1.2': [{'subnet': '192.1.211.0/24', 'cost':  1}, {'subnet': '192.1.213.0/24', 'cost': 1}, {'subnet': '10.1.1.2/32', 'cost': 1}, {'subnet': '10.1.101.0/24', 'cost': 1}, {'subnet': '192.1.212.0/24', 'cost': 1}, {'subnet': '192.1.220.0/24', 'cost': 10}, {'subnet': '192.1.210.0/24', 'cost': 1}, {'subnet': '10.1.12.0/24', 'cost': 10}]}
    elif test_num == 16:
        p2pOwnRidToOwnIpAddressDdDdMap = {'10.1.1.4': {'172.17.0.1': 1200, '192.16.0.1': 10}}
        p2pOwnIpAddressWithRemoteNeighborRidMap = {'172.17.0.1': '192.168.100.100', '192.16.0.1': '192.168.100.101'}
    elif test_num == 18:
        DrIpAddressToNeighborsRidSetMap = {'10.1.24.4': {'10.1.1.2', '10.1.1.4'}, '10.1.23.3': {'10.1.1.2', '10.1.1.3'}}
        drIpAddressToMetricMap = {'10.1.24.4': 100}
    elif test_num == 19:
        DrIpAddressToNeighborsRidSetMap = {'10.1.24.4': {'10.1.1.2', '10.1.1.4'}, '10.1.23.3': {'10.1.1.2', '10.1.1.3'}}
        OwnRidToOwnIpToDrIpAddressMap = {'10.1.123.24': {'10.1.123.24': '10.1.123.23'}, 
                                        '10.1.123.23': {'10.1.123.23': '10.1.123.23'}, 
                                        '10.1.1.2': {'10.1.123.1': '10.1.123.23', '10.1.24.2': '10.1.24.4'},
                                        '10.1.1.4': {'10.1.24.4': '10.1.24.4'}}
        drIpAddressToMetricMap = {'10.1.24.4': 100, '10.1.23.3': 10}
    graph_obj = GraphFromTopolograph()
    # not needed graph_obj.init_graph()
    #graph_obj = Graph(p2pOwnRidToOwnIpAddressDdDdMap, p2pOwnIpAddressWithRemoteNeighborRidMap, ospf_RID_to_stub_net, DrIpAddressToNeighborsRidSetMap, drIpAddressToMetricMap, OwnRidToOwnIpToDrIpAddressMap)
    # test15
    ##for adv_router_id, link_attr_dd in {'10.1.1.4': {'10.1.1.1': {'link_id': '10.1.1.1', 'link_data': '10.1.14.4', 'lsa_type': 1, 'metric': 10}, '192.168.100.100': {'link_id': '192.168.100.100', 'link_data': '172.17.0.1', 'lsa_type': 1, 'metric': 1000}}}.items():
    ##    hostToP2pMapFromGraph[adv_router_id].update(link_attr_dd)
    for line in follow(open("/var/log/quagga/ospfd.log", 'r')):
    #for line in follow(open(f"/home/ubuntu/watchlog/tests/test{test_num}.txt", 'r')):
        print(line, end='')
        # line parsinf
        #if re_mew_msg.match(line):
        #    parsedChangedLSA = {}
        '''
        2021/08/12 18:30:24 OSPF: Link State Update
        2021/08/12 18:30:24 OSPF:   # LSAs 1
        2021/08/12 18:30:24 OSPF:   LSA Header
        2021/08/12 18:30:24 OSPF:     LS age 3600
        2021/08/12 18:30:24 OSPF:     Options 34 (*|-|DC|-|-|-|E|-)
        2021/08/12 18:30:24 OSPF:     LS type 1 (router-LSA)
        2021/08/12 18:30:24 OSPF:     Link State ID 10.1.1.2
        2021/08/12 18:30:24 OSPF:     Advertising Router 10.1.1.2 <-- #re_adv_router_match#
        2021/08/12 18:30:24 OSPF:     LS sequence number 0x80000080
        2021/08/12 18:30:24 OSPF:     LS checksum 0x6b75
        2021/08/12 18:30:24 OSPF:     length 144

        2021/08/12 18:30:24 OSPF: Link State Update received from [10.1.1.4] via [gre1:172.17.0.100]
        2021/08/12 18:30:24 OSPF: -----------------------------------------------------
        2021/08/12 18:30:24 OSPF: SPF: Scheduled in 0 msec
        2021/08/12 18:30:25 OSPF: -----------------------------------------------------
        '''
        # New LSU
        if re_link_state_update.match(line):
            # we proceeded LSA1 or LSA2 later, but didn't match SPT log message
            if process_router_lsa:
                graph_obj.doGetNewOldDiffAllLsaOne(lsu_obj)
            if process_network_lsa:
                graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
            #LsuRouterLsaDetails = {} # include multiple advertising routers: LsuDetails = {'10.1.1.2': 'link_id': {router lsa details}}
            LsuNetworkLsaDetails = {} # {'10.1.1.2': [<attached routers list>]
            ## routerLsaDetails = {} # p2p, broadcast
            networkLsaDetails = {} # 
            process_lsa_header = False
            process_router_lsa = False
            process_network_lsa = False
            #lsa_age_sec = 0
            #lsa_adv_router_id = ''
            #lsa_link_state_id = ''
            lsu_obj = LSU()
        
        # New LSA Header
        if re_lsa_header.match(line):
            
            process_lsa_header = True
            # null values, because later could be Router LSA or Network LSA
            process_router_lsa = False # One LSU can include multiple LSA Headers with Router-LSA or Network-LSA
            process_network_lsa = False
            """
            Each new LSA header - we have to remember LSA age and adv router and save Network LSA with this attributes.
            """
            #if 'lsa_obj' in locals(): # `'lsa_obj' in locals` is needed when we first time to run script and lsa_obj is not defined yet.
            # BUG - REWRITE actual values by empty    graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
            lsa_obj = LSA(lsu_obj)          
        
        re_lsa_age_sec_match = re_lsa_age_sec.match(line)
        if process_lsa_header and re_lsa_age_sec_match:
            lsa_obj.age_sec = int(re_lsa_age_sec_match.groupdict().get('lsa_age_sec', 0))
        
        re_adv_router_match = re_adv_router.match(line)
        if process_lsa_header and re_adv_router_match:
            # New advertising Router ID.
            lsa_obj.adv_router_id = re_adv_router_match.groupdict().get('adv_router_id', '')
        
        re_lsa_link_state_id_match = re_lsa_link_state_id.match(line)
        if re_lsa_link_state_id_match:
            # lsa ID can include different meanings depends on lsa type
            lsa_obj.link_state_id = re_lsa_link_state_id_match.groupdict().get('link_state_id', '')

        # LSA1
        if re_router_lsa_header.match(line):
            process_router_lsa = True
        re_routerLsaLinkId_match = re_routerLsaLinkId.match(line)
        if process_router_lsa and re_routerLsaLinkId_match:
            tmp_router_lsa = {'link_id': re_routerLsaLinkId_match.groupdict().get('link_id', '')}
            #print(f'########:{tmp_router_lsa}')
        re_routerLsaLinkData_match = re_routerLsaLinkData.match(line)
        if process_router_lsa and re_routerLsaLinkData_match:
            tmp_router_lsa['link_data'] = re_routerLsaLinkData_match.groupdict().get('link_data', '')
        
        re_routerLsaType_match = re_routerLsaType.match(line)
        if process_router_lsa and re_routerLsaType_match:
            tmp_router_lsa['lsa_type'] = int(re_routerLsaType_match.groupdict().get('lsa_type', 0))

        re_routerLsaMetric_match = re_routerLsaMetric.match(line)
        if process_router_lsa and re_routerLsaMetric_match:
            # last record in Router LSA. Ready to save all previously parsed attributes
            tmp_router_lsa['metric'] = int(re_routerLsaMetric_match.groupdict().get('metric', ''))
            # add this LSA into LSU
            #print(lsa_obj.adv_router_id)

            #LsuRouterLsaDetails.setdefault(lsa_obj.adv_router_id, {}).update(routerLsaDetails)
            if tmp_router_lsa['lsa_type'] == 1:
                # make p2p object and add it to LSA obj automatically
                p2p_obj = P2PLSA(lsa_obj, tmp_router_lsa)
            elif tmp_router_lsa['lsa_type'] == 2:
                # lsa type 2 says about metric to DR IP address or set IP address of new DR
                transit_obj = TRANSIT_LSA(lsa_obj, tmp_router_lsa) # just add to LSA and keep all transit lsa in one list. With this list the script can detect missed transit connections
                # moved to doGetDiffTransit lsa_obj.isNewMetricOrNewDr_check(transit_obj, graph_obj=graph_obj)

            elif tmp_router_lsa['lsa_type'] == 3:
                # make stub object and add it to LSA obj automatically
                stub_obj = STUBLSA(lsa_obj, tmp_router_lsa)
        # LSA2
        if re_network_lsa_header.match(line):
            process_network_lsa = True
            # networkLsaDetails = {} # include all neighbors list
        re_networkLsaNetworkMask_match = re_networkLsaNetworkMask.match(line)
        if process_network_lsa and re_networkLsaNetworkMask_match:
            network_mask = re_networkLsaNetworkMask_match.groupdict().get('network_mask', '')
            lsa_obj.network_mask = network_mask
        re_networkLsaNeighbor_match = re_networkLsaNeighbor.match(line)
        if process_network_lsa and re_networkLsaNeighbor_match:
            # build a map with a list of DR neighbors
            lsa2_neighbor = re_networkLsaNeighbor_match.groupdict().get('lsa2_neighbor', '')
            # lsa_link_state_id = IP address of Desig. Rtr.
            #lsa_obj.dr_neigh_add(drIpAddress=lsa_link_state_id, lsa2_neighbor_rid=lsa2_neighbor)
            lsa_obj.dr_neigh_add(lsa2_neighbor_rid=lsa2_neighbor)

        #if re_end_line.match(line):
        #    if networkLsaDetails and lsa_link_state_id:
        #        DrIpAddressToNeighborsRidSetMap[ lsa_link_state_id ] = networkLsaDetails.get(lsa_link_state_id, {})
        #print(line, end='')
        if re_spf.match(line):
            #print(f"OSPF topology changes is detected. LsuRouterLsaDetails:{LsuRouterLsaDetails}")
            #if process_router_lsa and LsuRouterLsaDetails:
            if process_router_lsa:
                # check P2P links
                newP2pOwnIpAddressSet, oldP2pOwnIpAddressSet, changedP2pOwnIpAddressSet = graph_obj.doGetNewOldDiffP2p(lsu_obj)
                # check stub link
                newStubNetworkSet, oldStubNetworkSet, changedMetricStubNetworkSet = graph_obj.doGetNewOldDiffStub(lsu_obj)
                # change metrics on transit links are done after matching appropriate lsa type == 2
                graph_obj.doGetDiffTransit(lsu_obj)
                process_router_lsa = False # SPT can be printed several times after receiving msg, so proceed diff only one time
            if process_network_lsa:
                graph_obj.doGetNewOldLsa2Neighbors(lsa_obj)
                process_network_lsa = False # SPT can be printed several times after receiving msg, so proceed diff only one time
