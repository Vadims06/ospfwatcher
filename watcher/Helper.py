from collections import defaultdict
import ipaddress
import requests, os
import json
from requests.exceptions import Timeout
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from typing import Optional, Set, Annotated
import logging
import logging.handlers

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
        self.network_mask = '' # when LSA includes Network-LSA. list_state_id is also shared by Network LSA, because it includes DR IP address which correlates to the list of neighbors in Network LSA
        self.P2P_LSA_ll = []
        self.STUB_LSA_ll = []
        self.TRANSIT_LSA_ll = []
        self.process_router_lsa = False
        self.process_network_lsa = False
        # add itself to LSU
        lsu_obj.add_lsa(self)
        # Keep p2p neighbors (RID) map
        self.p2pOwnRidToOwnIpAddressDdDdMap: dict[RID, dict[IPAddress, Cost]] = defaultdict(dict) # {'10.100.0.1': {'192.168.100.4': 10, '192.168.101.4': 20}}. '10.100.0.1' has two interfaces to p2p neighbors via own interfaces '192.168.100.4' and '192.168.101.4' with cost 10 and 20 respectivelly
        # while we are saving own IP on p2p interface - we have to save mapping with our own IP address and neighbor OSPF RID on remote site
        self.p2pOwnIpAddressWithRemoteNeighborRidMap: dict[IPAddress, RID] = dict() # {'192.168.100.4': '10.100.0.2', '192.168.101.4': '10.100.0.3'} via own interface with IP 192.168.100.4 - OSPF neighbor with RID 10.100.0.2
        # Stub
        self.OwnRidToStubNetworkWithMaskToMetricMap = defaultdict(dict) # {'10.100.0.1': {'192.168.100.0/24': 10}}
        # LSA2 DR and his neighbors
        self.DrIpAddressToNeighborsRidSetMap = {} # 10.1.34.4 = IP address of DR, it's set is his neighbors RID {'10.1.34.4': {'10.1.1.3', '10.1.1.4'}, '10.1.23.3': {'10.1.1.3', '10.1.1.2'}}
        self.OwnRidToOwnIpToDrIpAddressToMetricMap: dict[RID, dict[IPAddress, dict[IPAddress, Cost]]] = dict() # {'10.1.1.4': {'192.168.123.24': {'192.168.123.1': 777}}}. the router with OSPF ID 10.1.1.4 has DR IP address 192.168.123.1 over his own IP 192.168.123.24. It's needed in order to distinguish DRs on different interfaces

    def add_p2p(self, p2p_obj) -> None:
        self.P2P_LSA_ll.append(p2p_obj)
        # build a map not with Neighbor's RID, but own IP address on the p2p interface
        self.p2pOwnRidToOwnIpAddressDdDdMap[p2p_obj.adv_router_id].setdefault(p2p_obj.ownP2pIpAddress, p2p_obj.metric)
        # while we are saving own IP on p2p interface - we have to save mapping with our own IP address and neighbor OSPF RID on remote site
        self.p2pOwnIpAddressWithRemoteNeighborRidMap[p2p_obj.ownP2pIpAddress] = p2p_obj.neighboringRouterID

    def add_stub(self, stub_obj) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[stub_obj.adv_router_id].setdefault(stub_obj.network, stub_obj.metric)

    def add_transit(self, transit_obj) -> None:
        self.TRANSIT_LSA_ll.append(transit_obj)
        self.OwnRidToOwnIpToDrIpAddressToMetricMap.setdefault(self.adv_router_id, {}).update({transit_obj.ownIPAddress: {transit_obj.drIpAddress: int(transit_obj.metric)}})

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


class TRANSIT_LSA:
    def __init__(self, lsa_obj, routerLsaDetails) -> None:
        """
        """
        self.drIpAddress = routerLsaDetails['link_id']
        self.ownIPAddress = routerLsaDetails['link_data']
        self.metric = routerLsaDetails['metric']

        # add to LSA
        lsa_obj.add_transit(self)

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
    def __init__(self, p2pOwnRidToOwnIpAddressDdDdMap, p2pOwnIpAddressWithRemoteNeighborRidMap, ospf_RID_to_stub_net, DrIpAddressToNeighborsRidSetMap, OwnRidToOwnIpToDrIpAddressToMetricMap, TranstiNetworksSet, graph_time) -> None:
        """
        ospf_RID_to_stub_net # {'192.168.1.1': [{'subnet': '10.100.0.0/24', 'cost': 10, 'area': 1/-1}]}, for EXT LSA5 - area -1
        Log the following actions:
        "event_name": "host" 
        "event_status": "up”/“down”

        "event_name": "metric", 
        "event_status": "changed",
        "subnet_type": "p2p”/"stub”/"transit"

        "event_name": "network", 
        "event_status": "up"/“down”
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
        self.OwnRidToOwnIpToDrIpAddressToMetricMap: dict[RID, dict[IPAddress, dict[IPAddress, Cost]]] = OwnRidToOwnIpToDrIpAddressToMetricMap # {'10.1.1.4': {'192.168.123.24': {'192.168.123.1': 777}}}. the router with OSPF ID 10.1.1.4 has DR IP address 192.168.123.1 over his own IP 192.168.123.24. It's needed in order to distinguish DRs on different interfaces
        self.TranstiNetworksSet: Set[NETWORK] = set(TranstiNetworksSet) # from API call we get a list, because a set is not json serializable
        
        # link between graph DB and changes DB
        self.graph_time = graph_time
        ## Calculated
        self.ipAddressToRidMap = {ip:rid for rid, ips_dd in self.OwnRidToOwnIpToDrIpAddressToMetricMap.items() for ip in ips_dd}

        # printing
        self.mformater = logging.Formatter('%(asctime)s,%(name)s,%(message)s', datefmt="%Y-%m-%dT%H:%M:%SZ") #'%Y-%m-%d %H:%M:%S'
        self.logfile = os.getenv('WATCHER_LOGFILE', os.path.join(os.path.dirname(__file__), 'tests/watcher.log'))
        self.hostUpDownLog_str = "host: {neighborName} {newStateUpDown}, detected by: {lsa_adv_router_id}"
        self.p2pUpDownLog_str = "{new_old} p2p neighbor: {neighborName}, detected by: {lsa_adv_router_id}"
        self.StubNetLog_str = "{new_old} stub network: {stubNetwork}, detected by: {lsa_adv_router_id}"

        self._setup_logging()

    def _setup_logging(self) -> None:
        self.logger_file = logging.getLogger(f"{os.getenv('WATCHER_NAME', 'watcher-local')}")
        self.logger_file.setLevel(logging.INFO)
        # Create a rotating file Handler.
        file_handler = logging.handlers.RotatingFileHandler(
            self.logfile,
            maxBytes=1000000,
            backupCount=1)
        file_handler.setFormatter(self.mformater)
        self.logger_file.addHandler(file_handler)
        # Errors
        error_file_handler = logging.FileHandler(self.logfile + '_errors.log')
        error_file_handler.setFormatter(self.mformater)
        error_file_handler.setLevel(logging.ERROR)
        self.logger_file.addHandler(error_file_handler)

    @staticmethod
    def prepareCsv(dd: dict) -> str:
        """
        Input {"event_name": "host", "event_object": "1.2.3.4", "event_status": "up", "event_detected_by": "10.1.1.4"}
        Output 'host,1.2.3.4,up,10.1.1.4'
        """
        return ','.join(map(str, dd.values()))

    def add_stub(self, adv_router_id, newStubNetwork, metric) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[adv_router_id].setdefault(newStubNetwork, metric)
    
    def del_stub(self, adv_router_id, oldStubNetwork) -> None:
        self.OwnRidToStubNetworkWithMaskToMetricMap[adv_router_id].pop(oldStubNetwork, '')
    
    def edit_metric_stub(self, adv_router_id, stubNetwork, metric) -> None: # TODO CHECK
        self.OwnRidToStubNetworkWithMaskToMetricMap.setdefault(adv_router_id, {}).update({stubNetwork: metric})

    def doParseStub(self, ospf_RID_to_stub_net) -> None:
        """
        {'192.168.1.1': [{'subnet': '10.100.0.0/24', 'cost': 10, 'area': 1/-1}]}, for EXT LSA5 - area -1
        """
        for adv_router_id, stub_attr_dd_ll in ospf_RID_to_stub_net.items():
            for stub_attr_dd in stub_attr_dd_ll:
                self.add_stub(adv_router_id, stub_attr_dd['subnet'], stub_attr_dd['cost'])

    def isTransitNetwork(self, networkWithDigitPrefix):
        return bool(networkWithDigitPrefix in self.TranstiNetworksSet)
    
    def del_from_transit_networks(self, networkWithDigitPrefix):
        """ the network can be removed from transit networks only if p2p connection will be establish across this network
        """
        self.TranstiNetworksSet -= {networkWithDigitPrefix}
    
    def add_to_transit_networks(self, networkWithDigitPrefix):
        """ the network can be removed from transit networks only if p2p connection will be establish across this network
        """
        self.TranstiNetworksSet.update({networkWithDigitPrefix})
    
    def changeDrToNew(self, oldDrIpAddress, newDrIpAddress, transit_lsa_obj, lsa_obj) -> None:
		# 1. Take all neighbors of old DR and replace old DR via his interface to new DR keeping their local interface cost To DR the same
        for neighborRid in self.DrIpAddressToNeighborsRidSetMap.get(oldDrIpAddress, []):
            _lsa_own_ip, _saved_metric_to_dr = self.getInterfaceIpToDr(neighborRid, oldDrIpAddress) # this method uses `for` but it iterate over only DR neighbors 
            if _lsa_own_ip:
                # do not use metric from LSA, because it's critical to save metric on remote neighbor TO dr. Metric from LSA shows metric from DR to neighbors
                self.OwnRidToOwnIpToDrIpAddressToMetricMap.setdefault(neighborRid, {}).update({_lsa_own_ip: {newDrIpAddress: _saved_metric_to_dr}})
            else: # the host doesn't have the record about the old DR on the link, so add it from LSA
                self.OwnRidToOwnIpToDrIpAddressToMetricMap.setdefault(lsa_obj.adv_router_id, {}).update({transit_lsa_obj.ownIPAddress: {transit_lsa_obj.drIpAddress: transit_lsa_obj.metric}})
        # 2. map all neighbors from old DR to the new one. Later the script will search a set of neighbors by new DR IP address in order to print old host ( when DR goes down)
        self.DrIpAddressToNeighborsRidSetMap[newDrIpAddress] = self.DrIpAddressToNeighborsRidSetMap.get(oldDrIpAddress, {})
        # empty neighbor list of old DR. As OSPF does - it include own host into neighbor list
        self.DrIpAddressToNeighborsRidSetMap[oldDrIpAddress] = {self.ipAddressToRidMap[oldDrIpAddress]} if oldDrIpAddress in self.ipAddressToRidMap else set()
    
    def isNewDrOrNewMetric(self, transit_lsa, lsa_obj) -> None:
        '''
        If new DR on shared segment is detected:
            1. copy a set of all old DR's neighbors to the new one.
            2. save which RID via which his local interface sees IP address of DR
        Check if metric to DR was changed
        '''
        # check probably LSA announces new IP address of DR ( when DR is down)
        saved_dr_ip_address_and_metric_items = tuple(self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(lsa_obj.adv_router_id, {}).get(transit_lsa.ownIPAddress, {}).items())
        saved_dr_ip_address, saved_metric_to_dr = saved_dr_ip_address_and_metric_items[0] if saved_dr_ip_address_and_metric_items else ('', 0)
        if not saved_dr_ip_address or not saved_metric_to_dr:
            self.OwnRidToOwnIpToDrIpAddressToMetricMap.setdefault(lsa_obj.adv_router_id, {}).update({transit_lsa.ownIPAddress: {transit_lsa.drIpAddress: int(transit_lsa.metric)}})
        if transit_lsa.ownIPAddress not in self.ipAddressToRidMap:
            self.ipAddressToRidMap[transit_lsa.ownIPAddress] = lsa_obj.adv_router_id
        if saved_dr_ip_address and transit_lsa.drIpAddress != saved_dr_ip_address:
            self.changeDrToNew(oldDrIpAddress = saved_dr_ip_address, newDrIpAddress = transit_lsa.drIpAddress, transit_lsa_obj=transit_lsa, lsa_obj=lsa_obj)

            ''' RFC
            A router that has formerly been the Designated Router for a
            network, but is no longer, should flush the network-LSA that
            it had previously originated.
            '''
        if transit_lsa.metric != saved_metric_to_dr:
            if int(saved_metric_to_dr) != 0: # when adjancecy is up, saved metric == 0
                print(f"changed transit metric. {self.ipAddressToRidMap.get(transit_lsa.ownIPAddress, '')}-{self.ipAddressToRidMap.get(transit_lsa.drIpAddress, '')} Old: {saved_metric_to_dr}, new: {transit_lsa.metric}. Detected by: {lsa_obj.adv_router_id}, shared_subnet_remote_neighbors_ids:{'_'.join(self.DrIpAddressToNeighborsRidSetMap.get(transit_lsa.drIpAddress, {lsa_obj.adv_router_id}))}")
                #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "old_cost", "new_cost", "event_detected_by"
                # _ is used in shared_subnet_remote_neighbors_ids because comma breaks csv parsing
                self.logger_file.info(self.prepareCsv({"event_name": "metric", 
                                                        "event_object": transit_lsa.ownIPAddress, 
                                                        "event_status": "changed",
                                                        "old_cost": f"old_cost:{saved_metric_to_dr}",
                                                        "new_cost": f"new_cost:{transit_lsa.metric}",
                                                        "event_detected_by": lsa_obj.adv_router_id,
                                                        "subnet_type": "transit",
                                                        "shared_subnet_remote_neighbors_ids": f"{'_'.join(self.DrIpAddressToNeighborsRidSetMap.get(transit_lsa.drIpAddress, {lsa_obj.adv_router_id}))}",
                                                        "graph_time": self.graph_time
                                                        }))
            if not self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(lsa_obj.adv_router_id, {}).get(transit_lsa.ownIPAddress):
                pass
            self.OwnRidToOwnIpToDrIpAddressToMetricMap.setdefault(lsa_obj.adv_router_id, {}).update({transit_lsa.ownIPAddress: {transit_lsa.drIpAddress: transit_lsa.metric}})
    
    def add_p2p_neighbor(self, lsa_obj, newP2pOwnIpAddress) -> None:
        # copy values from LSA
        newRid = lsa_obj.adv_router_id
        metric = lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[newRid][newP2pOwnIpAddress]
        remoteNeighborRid = lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress]
        # save tham into Graph object
        self.p2pOwnRidToOwnIpAddressDdDdMap.setdefault(newRid, dict()).setdefault(newP2pOwnIpAddress, metric)
        self.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress] = remoteNeighborRid
        # IF new Adjancency is up over ex-transit subnet - remove the subnet from the transit list
        try:
            ipaddress_obj = ipaddress.ip_interface(newP2pOwnIpAddress)
            for networkWithDigitMask in self.TranstiNetworksSet:
                network_obj = ipaddress.ip_network(networkWithDigitMask)
                if ipaddress_obj in network_obj:
                    self.del_from_transit_networks(networkWithDigitMask)
                    break
        except:
            pass
    
    def remove_p2p_neighbor(self, ownRid, oldP2pOwnIpAddress) -> None:
        self.p2pOwnRidToOwnIpAddressDdDdMap[ownRid].pop(oldP2pOwnIpAddress, '')
        self.p2pOwnIpAddressWithRemoteNeighborRidMap.pop(oldP2pOwnIpAddress, '')

    def edit_metric_p2p_neighbor(self, lsa_obj, p2pOwnIpAddress, new_metric) -> None:
        # copy values from LSA
        rid = lsa_obj.adv_router_id
        # save tham into Graph object
        self.p2pOwnRidToOwnIpAddressDdDdMap.setdefault(rid, dict()).setdefault(p2pOwnIpAddress, new_metric)

    @ifLSAcompleted
    def doGetNewOldDiffP2pSingleLSA(self, lsa_obj)-> tuple[set[IPAddress], set[IPAddress], set[IPAddress]]:
        # start to compare p2p interfaces. Why not neighbors - cos multiple adjuncencies can be bw two neighbors, but p2p interface is unique
        p2pOwnIpAddressSetFromGraph = set(self.p2pOwnRidToOwnIpAddressDdDdMap.get(lsa_obj.adv_router_id, {}).keys())
        p2pOwnIpAddressSetFromLSA = set(lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id].keys())

        newP2pOwnIpAddressSet = p2pOwnIpAddressSetFromLSA - p2pOwnIpAddressSetFromGraph
        for newP2pOwnIpAddress in newP2pOwnIpAddressSet:
            #print(f"new p2p neighbor: {lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress]}. Detected by: {lsa_obj.adv_router_id}")
            print(self.p2pUpDownLog_str.format(new_old = 'new',
                                        neighborName = lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress],
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
            #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
            self.logger_file.info(self.prepareCsv({"event_name": "host", 
                                                    "event_object": lsa_obj.p2pOwnIpAddressWithRemoteNeighborRidMap[newP2pOwnIpAddress], 
                                                    "event_status": "up", 
                                                    "event_detected_by": lsa_obj.adv_router_id,
                                                    "graph_time": self.graph_time
                                                    }))
            # add it to Graph
            self.add_p2p_neighbor(lsa_obj, newP2pOwnIpAddress)

        oldP2pOwnIpAddressSet = p2pOwnIpAddressSetFromGraph - p2pOwnIpAddressSetFromLSA
        for oldP2pOwnIpAddress in oldP2pOwnIpAddressSet:
            oldNeighborRid = self.p2pOwnIpAddressWithRemoteNeighborRidMap.get(oldP2pOwnIpAddress, oldP2pOwnIpAddress)
            #print(f"old p2p neighbor link: {oldNeighborRid}. Detected by: {lsa_obj.adv_router_id}")
            print(self.p2pUpDownLog_str.format(new_old = 'old',
                                        neighborName = oldNeighborRid,
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
            #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
            self.logger_file.info(self.prepareCsv({"event_name": "host", 
                                                    "event_object": oldNeighborRid, 
                                                    "event_status": "down", 
                                                    "event_detected_by": lsa_obj.adv_router_id,
                                                    "graph_time": self.graph_time
                                                    }))
            if not self.p2pOwnIpAddressWithRemoteNeighborRidMap.get(oldP2pOwnIpAddress):
                self.logger_file.error(self.prepareCsv({"event_name": "host", 
                                                        "event_object": oldP2pOwnIpAddress, 
                                                        "event_status": "down", 
                                                        "event_detected_by": lsa_obj.adv_router_id,
                                                        "graph_time": self.graph_time,
                                                        "error": f"there is no RID for p2p's IP address {oldP2pOwnIpAddress}"
                                                        }))
            '''
            # clear all stub nets of down node
            # In case of triangle connection, we remove stub networks if a link between two devices is Down, but we have backup path and Stub networks are available. Let's do not delete stub networks!
            '''
            # remove it from Graph
            self.remove_p2p_neighbor(lsa_obj.adv_router_id, oldP2pOwnIpAddress)
        
        changedP2pOwnIpAddressSet = set()
        for commonP2pOwnIpAddress in p2pOwnIpAddressSetFromGraph.intersection(p2pOwnIpAddressSetFromLSA):
            # compare metric on P2P links
            p2pMetricFromGraph = self.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id][commonP2pOwnIpAddress]
            p2pMetricFromLSA = lsa_obj.p2pOwnRidToOwnIpAddressDdDdMap[lsa_obj.adv_router_id][commonP2pOwnIpAddress]
            if p2pMetricFromGraph != p2pMetricFromLSA:
                print(f"changed p2p metric with {self.p2pOwnIpAddressWithRemoteNeighborRidMap[commonP2pOwnIpAddress]}. Old: {p2pMetricFromGraph}, new: {p2pMetricFromLSA}. Detected by: {lsa_obj.adv_router_id}")
                #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "old_cost", "new_cost", "event_detected_by"
                self.logger_file.info(self.prepareCsv({"event_name": "metric", 
                                                        "event_object": commonP2pOwnIpAddress, 
                                                        "event_status": "changed",
                                                        "old_cost": f"old_cost:{p2pMetricFromGraph}",
                                                        "new_cost": f"new_cost:{p2pMetricFromLSA}",
                                                        "event_detected_by": lsa_obj.adv_router_id,
                                                        "subnet_type": "p2p",
                                                        "shared_subnet_remote_neighbors_ids": f"{self.p2pOwnIpAddressWithRemoteNeighborRidMap[commonP2pOwnIpAddress]}",
                                                        "graph_time": self.graph_time
                                                        }))
                self.edit_metric_p2p_neighbor(lsa_obj, commonP2pOwnIpAddress, p2pMetricFromLSA)
                changedP2pOwnIpAddressSet.add(commonP2pOwnIpAddress)

        # return results only for test functions
        return newP2pOwnIpAddressSet, oldP2pOwnIpAddressSet, changedP2pOwnIpAddressSet

    @ifLSAcompleted
    def doGetNewOldDiffP2p(self, lsu_obj)-> tuple[set[IPAddress], set[IPAddress], set[IPAddress]]:
        newP2pOwnIpAddressSet_all = set()
        oldP2pOwnIpAddressSet_all = set()
        changedP2pOwnIpAddressSet_all = set()
        for lsa_obj in lsu_obj.LSA_ll:
                    
            # start to compare p2p interfaces. Why not neighbors - cos multiple adjuncencies can be bw two neighbors, but p2p interface is unique
            newP2pOwnIpAddressSet, oldP2pOwnIpAddressSet, changedP2pOwnIpAddressSet = self.doGetNewOldDiffP2pSingleLSA(lsa_obj)
            
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
            if self.isTransitNetwork(networkWithDigitPrefix=newStubNetwork):
                continue # # Initially transit network is shown as Stub network with type 3, Then adjancency with DR is up and this transit network disappears from type 3 and appears as type 2.
            #print(f"new stub network: {newStubNetwork}. Detected by: {lsa_obj.adv_router_id}")
            print(self.StubNetLog_str.format(new_old = 'new',
                                            stubNetwork = newStubNetwork,
                                            lsa_adv_router_id = lsa_obj.adv_router_id))
            #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
            self.logger_file.info(self.prepareCsv({"event_name": "network", 
                                                    "event_object": newStubNetwork, 
                                                    "event_status": "up", 
                                                    "event_detected_by": lsa_obj.adv_router_id,
                                                    "graph_time": self.graph_time
                                                    }))
            # add it to Graph
            self.add_stub(lsa_obj.adv_router_id, newStubNetwork, lsa_obj.OwnRidToStubNetworkWithMaskToMetricMap[lsa_obj.adv_router_id][newStubNetwork])

        oldStubNetworkSet = StubNetworkFromGraph - StubNetworkFromLSA
        for oldStubNetwork in oldStubNetworkSet:
            # Initially transit network is shown as Stub network with type 3, Then adjancency with DR is up and this transit network disappears from type 3 and appears as type 2. So the script prints it as stub network Down 

            if self.isTransitNetwork(networkWithDigitPrefix=oldStubNetwork):
                continue
            #print(f"old stub network: {oldStubNetwork}. Detected by: {lsa_obj.adv_router_id}")
            print(self.StubNetLog_str.format(new_old = 'old',
                                        stubNetwork = oldStubNetwork,
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
            #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
            self.logger_file.info(self.prepareCsv({"event_name": "network", 
                                                    "event_object": oldStubNetwork, 
                                                    "event_status": "down", 
                                                    "event_detected_by": lsa_obj.adv_router_id,
                                                    "graph_time": self.graph_time
                                                    }))
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
                #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
                self.logger_file.info(self.prepareCsv({"event_name": "metric", 
                                                        "event_object": commonStubNetwork, 
                                                        "event_status": "changed",
                                                        "old_cost": f"old_cost:{stubMetricFromGraph}",
                                                        "new_cost": f"new_cost:{stubMetricFromLSA}",
                                                        "event_detected_by": lsa_obj.adv_router_id,
                                                        "subnet_type": "stub",
                                                        "shared_subnet_remote_neighbors_ids": f"{lsa_obj.adv_router_id}",
                                                        "graph_time": self.graph_time
                                                        }))
                self.edit_metric_stub(lsa_obj.adv_router_id, commonStubNetwork, stubMetricFromLSA)
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

    def add_dr_neigh(self, drIpAddress, lsa2_neighbor_rid) -> None:
        self.DrIpAddressToNeighborsRidSetMap.setdefault(drIpAddress, set()).update(set([lsa2_neighbor_rid]))

    @ifLSAcompleted
    def doGetNewOldLsa2Neighbors(self, lsa_obj) -> tuple[set[RID], set[RID]]:
        # cycle over all LSAs is not needed here, because we print LSA neighbors changes every time when we detect new LSA Header
        drNeighborSetFromLSA = lsa_obj.DrIpAddressToNeighborsRidSetMap.get( lsa_obj.link_state_id, set() ) # lsa_obj.link_state_id - IP address of DR
        drNeighborSetFromGraph = self.DrIpAddressToNeighborsRidSetMap.get( lsa_obj.link_state_id, set() )
        if lsa_obj.age_sec == 3600:
            # All neighbors except Advertising Neighbor is down. Test 14.
            # changed.oldNeighbors = set(drNeighborSetFromGraph) - set([lsa_obj.adv_router_id]) # take all neighbors except adv router - they are old Neighbors 
            # changed.oldNeighbors = set(drNeighborSetFromGraph) - set(drNeighborSetFromLSA)
            oldNeighbors = set(drNeighborSetFromLSA) - {lsa_obj.adv_router_id}
            newNeighbors = set()
            # the list of neighbors are the same, but if age is equal to 3600, we have to update mapping
            #oldNeighbors.update({lsa_obj.adv_router_id})
            leftNeighborsRidSet = set(drNeighborSetFromGraph) - set(drNeighborSetFromLSA)
            leftNeighborsRidSet.update({lsa_obj.adv_router_id})
            self.DrIpAddressToNeighborsRidSetMap[ lsa_obj.link_state_id ] = leftNeighborsRidSet
            drNeighborSetFromGraph = self.DrIpAddressToNeighborsRidSetMap.get( lsa_obj.link_state_id, set() )
        else:
            # we need to compare list of neighbors
            oldNeighbors = set(drNeighborSetFromGraph) - set(drNeighborSetFromLSA)
            newNeighbors = set(drNeighborSetFromLSA) - set(drNeighborSetFromGraph)

            self.DrIpAddressToNeighborsRidSetMap[ lsa_obj.link_state_id ] = set(drNeighborSetFromLSA) - set(oldNeighbors)
        # Log missed routers
        for oldNeighborRid in oldNeighbors:
            # if a host was poweroffed so the script detects this from his neighbors, but the host doesn't send that his stub networks are also unavailable. We do it by itself

            if self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(oldNeighborRid): # remove info about transit network from this neighbor
                drIpAddress = self.getDrIpAddress(lsa_obj.adv_router_id, lsa_obj.link_state_id) 
                if lsa_obj.link_state_id == drIpAddress: # delete only if it's actual DR
                    own_ip, _ = self.getInterfaceIpToDr(own_rid=oldNeighborRid, dr_ip_address=drIpAddress)
                    self.__remove_transit_neighbor_from_data(oldNeighborRid, own_ip)
            self.doPrintHost(oldNeighborRid, 'Down', lsa_obj)
        
        for newNeighborRid in newNeighbors:
            self.doPrintHost(newNeighborRid, 'Up', lsa_obj)
            self.add_dr_neigh(drIpAddress=lsa_obj.link_state_id, lsa2_neighbor_rid=newNeighborRid)
        
        # update a list of neighbors linked to DR
        #if drNeighborSetFromLSA != drNeighborSetFromGraph:
        # BUUUG    self.DrIpAddressToNeighborsRidSetMap[ lsa_obj.link_state_id ] = set(drNeighborSetFromLSA) - set(oldNeighbors)

        return newNeighbors, oldNeighbors
    
    def getInterfaceIpToDr(self, own_rid, dr_ip_address) -> Optional[str]:
        """
        Iterate over all neighbors of DR and return of router's interface IP to the DR
        """
        for own_ip, _dr_ip_address_and_metric_dd in self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(own_rid, {}).items():
            if dr_ip_address in _dr_ip_address_and_metric_dd:
                return own_ip, _dr_ip_address_and_metric_dd[dr_ip_address]
        return '', ''
    
    def getDrIpAddress(self, ownRid: RID, transitOwnIpAddress: IPAddress) -> Optional[IPAddress]:
        saved_dr_ip_address_and_metric_items = tuple(self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(ownRid, {}).get(transitOwnIpAddress, {}).items())
        saved_dr_ip_address, _ = saved_dr_ip_address_and_metric_items[0] if saved_dr_ip_address_and_metric_items else ('', 0)
        return saved_dr_ip_address

    def getDrId(self, ownRid: RID, transitOwnIpAddress: IPAddress) -> Optional[IPAddress]:
        return self.ipAddressToRidMap[self.getDrIpAddress(ownRid, transitOwnIpAddress)]

    def isDr(self, ownRid: RID, transitOwnIpAddress: IPAddress) -> bool:
        saved_dr_ip_address_and_metric_items = tuple(self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(ownRid, {}).get(transitOwnIpAddress, {}).items())
        saved_dr_ip_address, _ = saved_dr_ip_address_and_metric_items[0] if saved_dr_ip_address_and_metric_items else ('', 0)
        return bool(transitOwnIpAddress == saved_dr_ip_address)
    
    def __remove_transit_neighbor_from_data(self, ownRid: RID, transitOwnIpAddress: IPAddress = '') -> None:
        try:
            if transitOwnIpAddress:
                del self.OwnRidToOwnIpToDrIpAddressToMetricMap[ownRid][transitOwnIpAddress]
            else:
                del self.OwnRidToOwnIpToDrIpAddressToMetricMap[ownRid]
        except:
            pass
    
    def remove_transit_not_dr_neighbor(self, ownRid: RID, transitOwnIpAddress: IPAddress = '') -> None:
        saved_dr_ip_address = self.getDrIpAddress(ownRid, transitOwnIpAddress)
        saved_dr_rid = self.getDrId(ownRid, transitOwnIpAddress)
        # from neighbor to Dr
        self.__remove_transit_neighbor_from_data(ownRid, transitOwnIpAddress)
        # delete from remote end
        # host Down is shown, but host UP - not, because remote end is not deleted
        # remove neighbor ID from DR's neigh list
        self.DrIpAddressToNeighborsRidSetMap[ saved_dr_ip_address ] -= {self.ipAddressToRidMap[transitOwnIpAddress]}
    
    def remove_transit_dr_neighbor(self, drIpAddress: IPAddress, transitOwnIpAddress: IPAddress = '') -> None:
        drRid = self.ipAddressToRidMap[drIpAddress]
        for neighborsRid in self.DrIpAddressToNeighborsRidSetMap.get(drIpAddress, []):
            # from neighbor to DR, but DR is also here
            neighborIp, _ = self.getInterfaceIpToDr(neighborsRid, drIpAddress) # this method uses `for` but it iterate over only DR neighbors 
            #if neighborIp and self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(neighborsRid, {}).get(neighborIp):
            if neighborsRid != drRid: # in order DR doesn't print itself as down
                # print(f"!!!host: {neighborsRid} Down. Detected by: {self.ipAddressToRidMap[transitOwnIpAddress]}")
                lsa_adv_router_id = self.ipAddressToRidMap[transitOwnIpAddress]
                if neighborsRid == lsa_adv_router_id:
                    # host 123.123.123.123 down, detected by 123.123.123.123
                    continue
                print(self.hostUpDownLog_str.format(neighborName = neighborsRid,
                                        newStateUpDown = 'Down',
                                        lsa_adv_router_id = lsa_adv_router_id))
                #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
                self.logger_file.info(self.prepareCsv({"event_name": "host", 
                                                        "event_object": neighborsRid, 
                                                        "event_status": "down", 
                                                        "event_detected_by": lsa_adv_router_id,
                                                        "graph_time": self.graph_time
                                                        }))
            # from neighbor to Dr, our DR itself
            self.__remove_transit_neighbor_from_data(neighborsRid, neighborIp)
            # delete from remote end, from DR to neighbor
            self.__remove_transit_neighbor_from_data(drRid, neighborIp)
        # remove neighbor ID from DR's neigh list
        self.DrIpAddressToNeighborsRidSetMap[ drIpAddress ] = {drRid}

    def doGetDiffTransitSingleLSA(self, lsa_obj) -> None:
        for transit_lsa in lsa_obj.TRANSIT_LSA_ll:
                # based on LSA1 - check existed and new DR. If DR is the same - leave unchanged
                # Does not detect missed DR 
                self.isNewDrOrNewMetric(transit_lsa, lsa_obj)

        transitOwnIpAddressSetFromGraph = set(self.OwnRidToOwnIpToDrIpAddressToMetricMap.get(lsa_obj.adv_router_id, {}).keys())
        transitOwnIpAddressSetFromLSA = set(lsa_obj.OwnRidToOwnIpToDrIpAddressToMetricMap.get(lsa_obj.adv_router_id, {}).keys())

        oldTransitOwnIpAddressSet = transitOwnIpAddressSetFromGraph - transitOwnIpAddressSetFromLSA
        
        for oldTransitOwnIpAddress in oldTransitOwnIpAddressSet:
            # miss if failed non-DR
            saved_dr_ip_address = self.getDrIpAddress(lsa_obj.adv_router_id, oldTransitOwnIpAddress)
            if self.isDr(lsa_obj.adv_router_id, oldTransitOwnIpAddress):
                #print(f'{oldTransitOwnIpAddress} is {self.ipAddressToRidMap[oldTransitOwnIpAddress]} DR. Host is down should be printed based on LSA2, if we receive it, but it is also OK to print Down host from Transit LSA ')
                self.remove_transit_dr_neighbor(saved_dr_ip_address, oldTransitOwnIpAddress)

            else:
                self.remove_transit_not_dr_neighbor(lsa_obj.adv_router_id, oldTransitOwnIpAddress)

                hostDownRid = self.ipAddressToRidMap[oldTransitOwnIpAddress]

                if hostDownRid == lsa_obj.adv_router_id:
                    hostDownRid = self.ipAddressToRidMap[saved_dr_ip_address]

                #print(f"!!host: {hostDownRid} Down. Detected by: {lsa_obj.adv_router_id}") # Print all neighbors
                if hostDownRid == lsa_obj.adv_router_id:
                    # host 123.123.123.123 down, detected by 123.123.123.123
                    continue
                print(self.hostUpDownLog_str.format(neighborName = hostDownRid,
                                    newStateUpDown = 'Down',
                                    lsa_adv_router_id = lsa_obj.adv_router_id))
                #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
                self.logger_file.info(self.prepareCsv({"event_name": "host", 
                                                        "event_object": hostDownRid, 
                                                        "event_status": "down", 
                                                        "event_detected_by": lsa_obj.adv_router_id,
                                                        "graph_time": self.graph_time
                                                        }))

    def doGetDiffTransit(self, lsu_obj) -> None:
        """
        Detect only old DRs. Because if there is no any neighbors on shared (transit) segment - a router doesn't announce that he is alone and he is DR. We should determine this
        """
        for lsa_obj in lsu_obj.LSA_ll:

            self.doGetDiffTransitSingleLSA(lsa_obj)
            
    def doGetNewOldDiffAllLsaOne(self, lsu_obj):
        self.doGetNewOldDiffP2p(lsu_obj)
        self.doGetNewOldDiffStub(lsu_obj)
        self.doGetDiffTransit(lsu_obj)

    def doPrintHost(self, neighborRid, newStateUpDown, lsa_obj):
        # Log string output
        # hostDownLog_str = "host: {neighborName} {newStateUpDown}, detected by: {lsa_adv_router_id}"
        #if newStateUpDown.lower() == 'down' and lsa_obj.link_state_id in self.ex_DrIpAddressSet:
        drIpAddress = self.getDrIpAddress(lsa_obj.adv_router_id, lsa_obj.link_state_id) 
        if lsa_obj.link_state_id != drIpAddress: # link_state_id - DR IP Address in case of LSA2
            #print(f"filtered {lsa_obj.adv_router_id} as Ex DR. Wanted to log. host: {neighborName} {newStateUpDown}, detected by: {lsa_obj.adv_router_id}")
            return
        if drIpAddress:
            if neighborRid == lsa_obj.adv_router_id:
                # host 123.123.123.123 down, detected by 123.123.123.123
                return
            print(self.hostUpDownLog_str.format(neighborName = neighborRid,
                                        newStateUpDown = newStateUpDown,
                                        lsa_adv_router_id = lsa_obj.adv_router_id))
            #"watcher_time","watcher_name"||"event_name", "event_object", "event_status", "event_detected_by"
            self.logger_file.info(self.prepareCsv({"event_name": "host", 
                                                    "event_object": neighborRid, 
                                                    "event_status": newStateUpDown.lower(), 
                                                    "event_detected_by": lsa_obj.adv_router_id,
                                                    "graph_time": self.graph_time
                                                    }))
            # if it's new host,  check that network is in transit. LSA2 includes network mask
            try:
                network_obj = ipaddress.ip_interface(f"{drIpAddress}/{lsa_obj.network_mask}")
                if not self.isTransitNetwork(str(network_obj.network)):
                    self.add_to_transit_networks(str(network_obj.network))
            except:
                pass

class QConnecter:
    _device = {
        'device_type': 'cisco_ios_telnet',
        "host": os.getenv('QUAGGA_HOST', '127.0.0.1'),
        "port": 2604,
        "password": os.getenv('QUAGGA_PASSWORD', 'zebra'),
        "secret": os.getenv('QUAGGA_SECRET', 'zebra'),
        }

    def do_check_if_ospf_has_neighbors(self):
        output = False
        try:
            with ConnectHandler(**self._device) as conn:
                show_ip_ospf_neigh_json_reply = conn.send_command('show ip ospf neighbor json')
                show_ip_ospf_neigh_reply = json.loads(show_ip_ospf_neigh_json_reply)
                output = bool(show_ip_ospf_neigh_reply.get("neighbors", False)) if show_ip_ospf_neigh_reply else False
        except (NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionRefusedError) as error:
            print(error, self._device)
        return output

    def get_lsdb_output(self):
        output_str = ''
        try:
            with ConnectHandler(**self._device) as conn:
                for command in ['show ip ospf database router', 'show ip ospf database network']:
                    output_str += conn.send_command(command)
        except (NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionRefusedError) as error:
            print(error, self._device)
        return output_str
    
    def do_enable_ospf_debug(self) -> None:
        try:
            with ConnectHandler(**self._device) as conn:
                conn.enable()
                conn.send_command('debug ospf packet ls-update recv detail')
                print('OSPF debug has been enabled')
        except (NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionRefusedError) as error:
            print(error, self._device)

class GraphFromTopolograph(Graph):

    def __init__(self) -> None:
        self._login, self._pass = os.getenv('TOPOLOGRAPH_WEB_API_USERNAME_EMAIL'), os.getenv('TOPOLOGRAPH_WEB_API_PASSWORD')
        self._host, self._port = os.getenv('TOPOLOGRAPH_HOST'), os.getenv('TOPOLOGRAPH_PORT')
        if not self._login and not self._pass:
            raise ValueError('credentials for connection to Topolograph are not set')
        self.init_graph()
    
    def init_graph(self):
        quagga_conn = QConnecter()
        if os.getenv('TEST_MODE', '') == 'True':
            print('Demo mode. Connection to OSPFd has been missed.')
            with open(os.path.join(os.path.dirname(__file__), 'tests/quagga_lsdb.txt')) as f:
                lsdb_output = f.read()
        else:
            lsdb_output = quagga_conn.get_lsdb_output()
            if not quagga_conn.do_check_if_ospf_has_neighbors():
                raise ValueError('Quagga does not have any neighbors, please setup GRE tunnel and build OSPF adjacency first.')
        print(f"lsdb_output:{lsdb_output[:200]}")
        if not lsdb_output:
            raise ValueError('Cannot get LSDB from Quagga Watcher')
        try:
            r_post = requests.post(f'http://{self._host}:{self._port}/api/watcher', auth=(self._login, self._pass), 
                            json={'lsdb_output': lsdb_output, 'vendor_device': 'Quagga'}, timeout=(5, 30))
        except Timeout:
            raise Timeout('The request timed out')
        if r_post.ok:
            print('OSPF LSDB has been received')
            if os.getenv('TEST_MODE', '') != 'True':
                quagga_conn.do_enable_ospf_debug()
            super().__init__(**r_post.json())
        else:
            try:
                print(f"r_post.text")
                _error = r_post.json()
                _error = _error.get('detail', '')
            except AttributeError:
                print(f"{r_post.reason}, {_error}")
            except ValueError:
                _error = r_post.text
                print(f"{_error}")
            raise ValueError(f"{r_post.reason}, {_error}")