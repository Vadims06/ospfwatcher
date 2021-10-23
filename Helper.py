from collections import defaultdict
import ipaddress
import requests, os
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from typing import Optional, Set, Union, List, Annotated

class General:
    def add_stub(self, obj, newStubNetwork, metric) -> None:
        metric = obj.OwnRidToStubNetworkWithMaskToMetricMap[obj.adv_router_id][newStubNetwork]
        self.OwnRidToStubNetworkWithMaskToMetricMap[obj.adv_router_id].setdefault(newStubNetwork, metric)

class LSU:
    def __init__(self) -> None:
        self.LSA_ll = []
    def add_lsa(self, lsa_obj) -> None:
        self.LSA_ll.append(lsa_obj)

RID = Annotated[str, "OSPF Router ID, i.e. 10.1.1.1"]
IPAddress = Annotated[str, "i.e. 10.1.1.1"]
NETWORK = Annotated[str, "i.e. 172.16.0.0/24"]
Cost = Annotated[int, 10]

class LSA:
    def __init__(self, lsu_obj) -> None:
        #self.adv_router_id = adv_router_id
        self.adv_router_id = ''
        #self.age_sec = age_sec
        self.age_sec = 0
        self.link_state_id = '' # Dr IP address in case of Network-LSA
        self.P2P_LSA_ll = []
        self.STUB_LSA_ll = []
        self.NET_LSA_ll = []
        # add itself to LSU
        lsu_obj.add_lsa(self)
        # Keep p2p neighbors (RID) map
        self.p2pOwnRidToOwnIpAddressDdDdMap: dict[RID, dict[IPAddress, Cost]] = defaultdict(dict) # {'10.100.0.1': {'192.168.100.4': 10, '192.168.101.4': 20}}. '10.100.0.1' has two interfaces to p2p neighbors via own interfaces '192.168.100.4' and '192.168.101.4' with cost 10 and 20 respectivelly
        # while we are saving own IP on p2p interface - we have to save mapping with our own IP address and neighbor OSPF RID on remote site
        self.p2pOwnIpAddressWithRemoteNeighborRidMap: dict[IPAddress, RID] = dict() # {'192.168.100.4': '10.100.0.2', '192.168.101.4': '10.100.0.3'} via own interface with IP 192.168.100.4 - OSPF neighbor with RID 10.100.0.2
        # Stub
        self.OwnRidToStubNetworkWithMaskToMetricMap = defaultdict(dict) # {'10.100.0.1': {'192.168.100.0/24': 10}}
        # Metric to DR IP address
        self.drIpAddressToMetricMap: dict[IPAddress, Cost] = {} # 10.1.34.4 = IP address of DR, 1000 - metric {'10.1.34.4': 1000}
        # LSA2 DR and his neighbors
        self.DrIpAddressToNeighborsRidSetMap = {} # 10.1.34.4 = IP address of DR, it's set is his neighbors RID {'10.1.34.4': {'10.1.1.3', '10.1.1.4'}, '10.1.23.3': {'10.1.1.3', '10.1.1.2'}}

    def add_p2p(self, p2p_obj) -> None:
        self.P2P_LSA_ll.append(p2p_obj)
        # build a map not with Neighbor's RID, but own IP address on the p2p interface
        self.p2pOwnRidToOwnIpAddressDdDdMap[p2p_obj.adv_router_id].setdefault(p2p_obj.ownP2pIpAddress, p2p_obj.metric)
        # while we are saving own IP on p2p interface - we have to save mapping with our own IP address and neighbor OSPF RID on remote site
        self.p2pOwnIpAddressWithRemoteNeighborRidMap[p2p_obj.ownP2pIpAddress] = p2p_obj.neighboringRouterID

    def add_stub(self, stub_obj) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[stub_obj.adv_router_id].setdefault(stub_obj.network, stub_obj.metric)

    def __getInterfaceIpToDr(self, graph_obj, own_rid, dr_ip_address) -> Optional[str]:
        """
        Iterate over all neighbors of DR and return of router's interface IP to the DR
        """
        for own_ip, _dr_ip_address in graph_obj.OwnRidToOwnIpToDrIpAddressMap.get(own_rid, {}).items():
            if _dr_ip_address == dr_ip_address:
                return own_ip

    def isNewMetricOrNewDr_check(self, tmp_router_lsa, graph_obj) -> None:
        """
        If new DR on shared segment is detected - copy a set of all old DR's neighbors to the new one. Additionally, save which RID via which his local interface see IP address of DR
        Check if metric to DR was changed
        """
        # check probably LSA announces new IP address of DR ( when DR is down)
        lsa_metric = tmp_router_lsa['metric']
        lsa_dr_ip_address = tmp_router_lsa['link_id']
        lsa_own_ip = tmp_router_lsa['link_data']
        saved_dr_ip_address = graph_obj.OwnRidToOwnIpToDrIpAddressMap.get(self.adv_router_id, {}).get(lsa_own_ip, '')
        if saved_dr_ip_address and lsa_dr_ip_address != saved_dr_ip_address:
            # 1. Take all neighbors of old DR and associate with new DR
            for neighborsRid in graph_obj.DrIpAddressToNeighborsRidSetMap[saved_dr_ip_address]:
                if neighborsRid != self.adv_router_id:
                    lsa_own_ip = self.__getInterfaceIpToDr(graph_obj, neighborsRid, saved_dr_ip_address) # this method uses `for` but it iterate over only DR neighbors 
                if lsa_own_ip:
                    graph_obj.OwnRidToOwnIpToDrIpAddressMap.setdefault(neighborsRid, {}).update({lsa_own_ip: lsa_dr_ip_address})
            # 2. map all neighbors from old DR to the new one
            graph_obj.DrIpAddressToNeighborsRidSetMap[lsa_dr_ip_address] = graph_obj.DrIpAddressToNeighborsRidSetMap.get(saved_dr_ip_address, [])
            # empty neighbor list of old DR
            graph_obj.DrIpAddressToNeighborsRidSetMap[saved_dr_ip_address] = []

            # 3. copy DR's metric
            saved_metric = graph_obj.drIpAddressToMetricMap.get(saved_dr_ip_address, 0)
            graph_obj.drIpAddressToMetricMap[lsa_dr_ip_address] = saved_metric
            if saved_dr_ip_address in graph_obj.drIpAddressToMetricMap:
                graph_obj.drIpAddressToMetricMap.pop(saved_dr_ip_address)
        self.drIpAddressToMetricMap[lsa_dr_ip_address] = lsa_metric
    
    def dr_neigh_add(self, lsa2_neighbor_rid) -> None:
        # keep LSA2 neighbor list per LSA, not per LSU, because we need LSA Age, and it's property of LSA
        self.DrIpAddressToNeighborsRidSetMap.setdefault(self.link_state_id, set()).update(set([lsa2_neighbor_rid]))


class P2PLSA:
    def __init__(self, lsa_obj, routerLsaDetails) -> None:
        """
        routerLsaDetails =
        {link_id:, link_data:, lsa_type: 1, metric:}
        """
        assert int(routerLsaDetails['lsa_type']) == 1, 'point-to-point LSA has to have type 1'

        self.neighboringRouterID = routerLsaDetails['link_id']
        self.ownP2pIpAddress = routerLsaDetails['link_data']
        self.metric = int(routerLsaDetails['metric'])
        self.adv_router_id = lsa_obj.adv_router_id
        
        lsa_obj.add_p2p(self)


class STUBLSA:
    def __init__(self, lsa_obj, routerLsaDetails) -> None:
        """
        routerLsaDetails =
        {link_id:, link_data:, lsa_type: 3, metric:}
        """
        try:
            subnet_with_digit_mask = str(ipaddress.IPv4Interface('{subnet}/{hex_mask}'.format(subnet=routerLsaDetails['link_id'], hex_mask=routerLsaDetails['link_data'])).network)
            self.network = subnet_with_digit_mask
            self.metric = routerLsaDetails['metric']
            self.adv_router_id = lsa_obj.adv_router_id
            # add to LSA
            lsa_obj.add_stub(self)
        except:
            pass


class NETLSA2: # not used
    def __init__(self, drIpAddress) -> None:
        """
        Keep a mapping of all members of DR router
        """
        self.drIpAddress = drIpAddress
        self.drNeighborsRIDset = set()
    
def ifLSAcompleted(method):
    """
    This decorator is needed in order to make sure that LSA Header is filled/parsed correctly 
    """
    def inner(ref, *args, **kwargs):
        lsa_obj_ll = list(filter(lambda x: isinstance(x, LSA), args))
        lsa_obj_ll.extend(list(filter(lambda x: isinstance(x, LSA), kwargs)))
        for lsa_obj in lsa_obj_ll:
            if not bool(lsa_obj.age_sec and lsa_obj.adv_router_id and lsa_obj.link_state_id):
                raise ValueError('LSA object is not completed')
            else:
                return method(ref, *args, **kwargs)
        else:
            # do not include LSA object
            return method(ref, *args, **kwargs)
    return inner

class Graph:
    def __init__(self, p2pOwnRidToOwnIpAddressDdDdMap, p2pOwnIpAddressWithRemoteNeighborRidMap, ospf_RID_to_stub_net, DrIpAddressToNeighborsRidSetMap, drIpAddressToMetricMap, OwnRidToOwnIpToDrIpAddressMap) -> None:
        """
        ospf_RID_to_stub_net # {'192.168.1.1': [{'subnet': '10.100.0.0/24', 'cost': 10, 'area': 1/-1}]}, for EXT LSA5 - area -1
        """
        self.p2pOwnRidToOwnIpAddressDdDdMap: dict[RID, dict[IPAddress, Cost]] = p2pOwnRidToOwnIpAddressDdDdMap # {'10.100.0.1': {'192.168.100.4': 10, '192.168.101.4': 20}}. '10.100.0.1' has two interfaces to p2p neighbors via own interfaces '192.168.100.4' and '192.168.101.4' with cost 10 and 20 respectivelly
        self.p2pOwnIpAddressWithRemoteNeighborRidMap: dict[IPAddress, RID] = p2pOwnIpAddressWithRemoteNeighborRidMap # {'192.168.100.4': '10.100.0.2', '192.168.101.4': '10.100.0.3'} via own interface with IP 192.168.100.4 - OSPF neighbor with RID 10.100.0.2
        self.P2P_LSA_ll = []

        # Stub networks
        self.OwnRidToStubNetworkWithMaskToMetricMap = defaultdict(dict) # {'10.100.0.1': {'192.168.100.0/24': 10}}
        # fill Stub
        self.doParseStub(ospf_RID_to_stub_net)

        # LSA2 info
        self.DrIpAddressToNeighborsRidSetMap: dict[IPAddress, Set[RID]] = {drIpAddress:set(NeighborsRidList) for drIpAddress, NeighborsRidList in DrIpAddressToNeighborsRidSetMap.items()}
        self.OwnRidToOwnIpToDrIpAddressMap: dict[RID, dict[IPAddress, IPAddress]] = OwnRidToOwnIpToDrIpAddressMap # {'10.1.1.4': {'192.168.123.24': '192.168.123.1'}}. the router with OSPF ID 10.1.1.4 has DR IP address 192.168.123.1 over his own IP 192.168.123.24. It's needed in order to distinguish DRs on different interfaces
        self.drIpAddressToMetricMap: dict[IPAddress, Cost] = drIpAddressToMetricMap

    def add_stub(self, adv_router_id, newStubNetwork, metric) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[adv_router_id].setdefault(newStubNetwork, metric)
    
    def del_stub(self, adv_router_id, oldStubNetwork) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[adv_router_id].pop(oldStubNetwork, '')

    def doParseStub(self, ospf_RID_to_stub_net) -> None:
        """
        {'192.168.1.1': [{'subnet': '10.100.0.0/24', 'cost': 10, 'area': 1/-1}]}, for EXT LSA5 - area -1
        """
        tmp_router_lsa_ll = []
        for adv_router_id, stub_attr_dd_ll in ospf_RID_to_stub_net.items():
            for stub_attr_dd in stub_attr_dd_ll:
                self.add_stub(adv_router_id, stub_attr_dd['subnet'], stub_attr_dd['cost'])

    def add_p2p_neighbor(self, lsa_obj, newP2pOwnIpAddress) -> None:
        # copy values from LSA
        newRid = lsa_obj.adv_router_id
        metric = lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[newRid][newP2pOwnIpAddress]
        remoteNeighborRid = lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress]
        # save tham into Graph object
        self.p2pOwnRidToOwnIpAddressDdDdMap.setdefault(newRid, dict()).setdefault(newP2pOwnIpAddress, metric)
        self.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress] = remoteNeighborRid
    
    def remove_p2p_neighbor(self, ownRid, oldP2pOwnIpAddress) -> None:
        self.p2pOwnRidToOwnIpAddressDdDdMap[ownRid].pop(oldP2pOwnIpAddress, '')
        self.p2pOwnIpAddressWithRemoteNeighborRidMap.pop(oldP2pOwnIpAddress, '')

    @ifLSAcompleted
    def doGetNewOldDiffP2p(self, lsu_obj)-> tuple[set[IPAddress], set[IPAddress], set[IPAddress]]:
        newP2pOwnIpAddressSet_all = set()
        oldP2pOwnIpAddressSet_all = set()
        changedP2pOwnIpAddressSet_all = set()
        for lsa_obj in lsu_obj.LSA_ll:
                    
            # start to compare p2p interfaces. Why not neighbors - cos multiple adjuncencies can be bw two neighbors, but p2p interface is unique
            
            p2pOwnIpAddressSetFromGraph = set(self.p2pOwnRidToOwnIpAddressDdDdMap.get(lsa_obj.adv_router_id, {}).keys())
            p2pOwnIpAddressSetFromLSA = set(lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id].keys())

            newP2pOwnIpAddressSet = p2pOwnIpAddressSetFromLSA - p2pOwnIpAddressSetFromGraph
            for newP2pOwnIpAddress in newP2pOwnIpAddressSet:
                print(f"new p2p neighbor link: {lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress]}. Detected by: {lsa_obj.adv_router_id}")
                # add it to Graph
                self.add_p2p_neighbor(lsa_obj, newP2pOwnIpAddress)

            oldP2pOwnIpAddressSet = p2pOwnIpAddressSetFromGraph - p2pOwnIpAddressSetFromLSA
            for oldP2pOwnIpAddress in oldP2pOwnIpAddressSet:
                print(f"old p2p neighbor link: {self.p2pOwnIpAddressWithRemoteNeighborRidMap[oldP2pOwnIpAddress]}. Detected by: {lsa_obj.adv_router_id}")
                # remove it from Graph
                self.remove_p2p_neighbor(lsa_obj.adv_router_id, oldP2pOwnIpAddress)
            
            changedP2pOwnIpAddressSet = set()
            for commonP2pOwnIpAddress in p2pOwnIpAddressSetFromGraph.intersection(p2pOwnIpAddressSetFromLSA):
                # compare metric on P2P links
                p2pMetricFromGraph = self.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id][commonP2pOwnIpAddress]
                p2pMetricFromLSA = lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id][commonP2pOwnIpAddress]
                if p2pMetricFromGraph != p2pMetricFromLSA:
                    print(f"changed p2p metric with {self.p2pOwnIpAddressWithRemoteNeighborRidMap[commonP2pOwnIpAddress]}. Old: {p2pMetricFromGraph}, new: {p2pMetricFromLSA}. Detected by: {lsa_obj.adv_router_id}")
                    changedP2pOwnIpAddressSet.add(commonP2pOwnIpAddress)
            newP2pOwnIpAddressSet_all.update(newP2pOwnIpAddressSet)
            oldP2pOwnIpAddressSet_all.update(oldP2pOwnIpAddressSet)
            changedP2pOwnIpAddressSet_all.update(changedP2pOwnIpAddressSet)
        # return results only for test functions
        return newP2pOwnIpAddressSet_all, oldP2pOwnIpAddressSet_all, changedP2pOwnIpAddressSet_all
    
    @ifLSAcompleted
    def doGetNewOldDiffStubSingleLSA(self, lsa_obj) -> tuple[set[NETWORK], set[NETWORK], set[NETWORK]]:
        StubNetworkFromGraph = set(self.OwnRidToStubNetworkWithMaskToMetricMap.get(lsa_obj.adv_router_id, {}).keys())
        StubNetworkFromLSA = set(lsa_obj.OwnRidToStubNetworkWithMaskToMetricMap[lsa_obj.adv_router_id].keys())

        newStubNetworkSet = StubNetworkFromLSA - StubNetworkFromGraph
        for newStubNetwork in newStubNetworkSet:
            print(f"new stub network: {newStubNetwork}. Detected by: {lsa_obj.adv_router_id}")
            # add it to Graph
            self.add_stub(lsa_obj.adv_router_id, newStubNetwork, lsa_obj.OwnRidToStubNetworkWithMaskToMetricMap[lsa_obj.adv_router_id][newStubNetwork])

        oldStubNetworkSet = StubNetworkFromGraph - StubNetworkFromLSA
        for oldStubNetwork in oldStubNetworkSet:
            print(f"old stub network: {oldStubNetwork}. Detected by: {lsa_obj.adv_router_id}")
            # remove it from Graph
            self.adv_router_id = lsa_obj.adv_router_id # for using common method
            self.del_stub(lsa_obj.adv_router_id, oldStubNetwork)
        
        changedMetricStubNetworkSet = set()
        for commonStubNetwork in StubNetworkFromGraph.intersection(StubNetworkFromLSA):
            # compare metric on P2P links
            stubMetricFromGraph = self.OwnRidToStubNetworkWithMaskToMetricMap[lsa_obj.adv_router_id][commonStubNetwork]
            stubMetricFromLSA = lsa_obj.OwnRidToStubNetworkWithMaskToMetricMap[lsa_obj.adv_router_id][commonStubNetwork]
            if stubMetricFromGraph != stubMetricFromLSA:
                print(f"changed stub network metric {commonStubNetwork}. Old: {stubMetricFromGraph}, new: {stubMetricFromLSA}. Detected by: {lsa_obj.adv_router_id}")
                changedMetricStubNetworkSet.add(commonStubNetwork)
        return newStubNetworkSet, oldStubNetworkSet, changedMetricStubNetworkSet


    def doGetNewOldDiffStub(self, lsu_obj) -> tuple[set[NETWORK], set[NETWORK], set[NETWORK]]:
        newStubNetworkSet_all = set()
        oldStubNetworkSet_all = set()
        changedMetricStubNetworkSet_all = set()
        for lsa_obj in lsu_obj.LSA_ll:

            newStubNetworkSet, oldStubNetworkSet, changedMetricStubNetworkSet = self.doGetNewOldDiffStubSingleLSA(lsa_obj)
            newStubNetworkSet_all.update(newStubNetworkSet)
            oldStubNetworkSet_all.update(oldStubNetworkSet)
            changedMetricStubNetworkSet_all.update(changedMetricStubNetworkSet)
        return newStubNetworkSet_all, oldStubNetworkSet_all, changedMetricStubNetworkSet_all
    
    @ifLSAcompleted
    def doGetNewOldLsa2Neighbors(self, lsa_obj) -> tuple[set[RID], set[RID]]:
        # Log string output
        hostDownLog_str = "host: {neighborName} {newStateUpDown}, detected by: {lsa_adv_router_id}"
        # cycle over all LSAs is not needed here, because we print LSA neighbors changes every time when we detect new LSA Header
        drNeighborSetFromLSA = lsa_obj.DrIpAddressToNeighborsRidSetMap.get( lsa_obj.link_state_id, set() ) # lsa_obj.link_state_id - IP address of DR
        drNeighborSetFromGraph = self.DrIpAddressToNeighborsRidSetMap.get( lsa_obj.link_state_id, set() )
        if lsa_obj.age_sec == 3600:
            # All neighbors except Advertising Neighbor is down. Test 14.
            oldNeighbors = set(drNeighborSetFromGraph) - set([lsa_obj.adv_router_id]) # take all neighbors except adv router - they are old Neighbors 
            newNeighbors = set()
        else:
            # we need to compare list of neighbors
            oldNeighbors = set(drNeighborSetFromGraph) - set(drNeighborSetFromLSA)
            newNeighbors = set(drNeighborSetFromLSA) - set(drNeighborSetFromGraph)
        # Log missed routers
        print(f'old hosts: {oldNeighbors}')
        print(f'new hosts: {newNeighbors}')
        for oldNeighborName in oldNeighbors:
            print(hostDownLog_str.format(neighborName = oldNeighborName,
                                        newStateUpDown = 'Down',
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
        
        for newNeighborName in newNeighbors:
            print(hostDownLog_str.format(neighborName = newNeighborName,
                                        newStateUpDown = 'Up',
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
        # update a list of neighbors linked to DR
        print('update a list of neighbors linked to DR')
        self.DrIpAddressToNeighborsRidSetMap[ lsa_obj.adv_router_id ] = set(drNeighborSetFromLSA) - set(oldNeighbors)

        return newNeighbors, oldNeighbors
 
    def doGetDiffTransit(self, lsu_obj) -> None:
        for lsa_obj in lsu_obj.LSA_ll:
            # take all transit networks to DRs and compare metric, then pring changed metric to all neighbors to DR 
            for commonDrIpAddress in set(self.drIpAddressToMetricMap.keys()).intersection(set(lsa_obj.drIpAddressToMetricMap.keys())):
                toDrMetricFromGraph = self.drIpAddressToMetricMap[commonDrIpAddress] 
                toDrMetricFromLSA = lsa_obj.drIpAddressToMetricMap[commonDrIpAddress]
                if toDrMetricFromGraph != toDrMetricFromLSA:
                    for NeighborsRid in self.DrIpAddressToNeighborsRidSetMap[commonDrIpAddress]:
                        print(f"changed transit metric with {NeighborsRid}. Old: {toDrMetricFromGraph}, new: {toDrMetricFromLSA}. Detected by: {lsa_obj.adv_router_id}")
                        # update metric to new
                        self.drIpAddressToMetricMap[commonDrIpAddress] = toDrMetricFromLSA

class QConnecter:
    _device = {
        'device_type': 'cisco_ios_telnet',
        "host": '127.0.0.1',
        "port": 2604,
        "password": 'zebra',
        }

    def get_lsdb_output(self):
        output_str = ''
        try:
            with ConnectHandler(**self._device) as conn:
                for command in ['show ip ospf database router', 'show ip ospf database network']:
                    output_str += conn.send_command(command)
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            print(error)
        return output_str

class GraphFromTopolograph(Graph):

    def __init__(self) -> None:

        quagga_conn = QConnecter()
        lsdb_output = quagga_conn.get_lsdb_output()
        if not lsdb_output:
            raise ValueError('Cannot get LSDB from Quagga Watcher')
        _login, _pass = os.getenv('TOPOLOGRAPH_USER_LOGIN'), os.getenv('TOPOLOGRAPH_USER_PASS')
        if not _login and not _pass:
            raise ValueError('credentials for connection to Topolograph are not set')
        r_post = requests.post('https://topolograph.com/api/graph', auth=(_login, _pass), 
                          json={'lsdb_output': lsdb_output, 'vendor_device': 'Quagga'})
        print(r_post.json())
        #super().__init__()