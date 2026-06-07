# OSPF watcher. Tracking OSPF topology changes in Real-Time

![OSPF watcher containerlab](ospfwatcher_containerlab.png)
This lab consists of 6 FRR routers and a single OSPF Watcher. Each router is pre-configured to be part of an OSPF domain with different network types. Any topology changes detected by the OSPF Watcher are logged in the file `watcher/watcher.log`. The logging capabilities can be enhanced with tools like ELK or Topolograph, enabling features such as searching changes by time and exporting data to message brokers, Zabbix, and more. For further details, refer to the Links page.

### OSPF Topology Watcher
OSPF Watcher is a monitoring tool of OSPF topology changes for network engineers. It works via passively listening to OSPF control plane messages through a specially established OSPF adjacency between OSPF Watcher and one of the network device. *It assists in analyzing incidents by determining the precise time and location of events, as well as their distribution across the network in a retrospective manner.*  

#### Detected network events:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appearance/disappearance from the topology
* OSPF TE attributes (RFC 3630): Administrative Group, Maximum Link Bandwidth, Maximum Reservable Link Bandwidth, Unreserved Bandwidth, Traffic Engineering Default Metric

## Quickstart
> [!NOTE]
> To connect to routers use telnet 127.0.0.1 6500N where N is a router number, or use sudo docker exec -it clab-ospf01-router6 vtysh

1. [Install](https://containerlab.srlinux.dev/install/) containerlab.
2. Run the script to prepare environment:

    ```
    sudo ./prepare.sh
    ```

3. Start the lab
    ```
    sudo clab deploy --topo ospf01.clab.yml
    ```

4. Check that Watcher is ready (usually it requires 10-15sec to be ready). Proceed to the next step once Watcher is ready.  
    ```
    sudo docker logs clab-ospf01-ospf-watcher
    ```
    Expected output:
    ```
    lsdb_output:
    OSPF Instance: 1


        OSPF Router with ID (10.10.10.1)


                    Router Link States (Area 0.0.0.0)

    LS age: 9
    Options: 0x2  : *|-|-|-|-|-|E|-
    LS Flags: 0x3
    Flags: 0x0
    LS Type:
    OSPF LSDB has been received
    Sniffing packets on interface: eth1
    ```

5. Start watching logs
    ```
    sudo tail -f watcher/logs/watcher1.ospf.log
    ```

6. Change OSPF settings on lab' routers. Connect to a router
    ```
    sudo docker exec -it clab-ospf01-router6 vtysh
    ```
    6.1    Change metric on the interface
    ```
    router6# conf t
    router6(config)# int eth1
    router6(config-if)# ip ospf cost 66
    ```

    6.2    Add new stub network
    ```
    router6(config-if)# ip address 10.10.136.6/24
    ```

    6.3 Change TE attributes.   
    ```
    router6(config)# int eth1
    router6(config-if)# link-params
    router6(config-link-params)# metric 100
    router6(config-link-params)# admin-grp 0xaa
    router6(config-link-params)# unrsv-bw 0 1e+07
    router6(config-link-params)# max-bw 2e+08
    ```

    6.4 Remove external type-2 subnet
    ```
    router6(config-if)# exit
    router6(config)# no ip route 6.6.6.6/32 192.168.36.3
    ```

    6.5 Shutdown adjancency
    ```
    router6(config)# int eth1
    router6(config-if)# shutdown
    ```

    6.6 Unshutdown adjancency
    ```
    router6(config)# int eth1
    router6(config-if)# no shutdown
    ```

### OSPF Watcher logs location
Available under `watcher` folder. To see them:
```
sudo tail -f watcher/watcher.log
```


##### Logs sample 1  
```
2023-01-01T00:00:00Z,demo-watcher,host10.10.10.4,down,10.10.10.5,01Jan2023_00h00m00s_7_hosts,0,1234,192.168.145.5,,981e52b4-175b-11f1-b65c-c25d5799b044,10.10.10.1
```

* `2023-01-01T00:00:00Z` - event timestamp
* `demo-watcher` - name of watcher
* `host` - event name: `host`, `network`, `metric`
* `10.10.10.4` - event object. Watcher detected an event related to `10.10.10.4` host
* `down` - event status: `down`, `up`, `changed`
* `10.10.10.5` - event detected by this node.
* `01Jan2023_00h00m00s_7_hosts` - name of graph in Topolograph dashboard
* `0.0.0.0` - OSPF area ID
* `1234` - AS number where OSPF is working
* `192.168.145.5` - IP address on detected node
* `` - empty remote IP address
* `981e52b4-175b-11f1-b65c-c25d5799b044` - session ID, the same session till next LSDB update
* `10.10.10.1` - source ID
*Summary: `10.10.10.5` detected that `10.10.10.4` host on the interface with `192.168.145.5` IP address in area 0 in AS 1234 went down at `2023-01-01T00:00:00Z`*

##### Logs sample 2  
```
2023-01-01T00:00:00Z,demo-watcher,network,192.168.13.0/24,changed,old_cost:10,new_cost:12,10.10.10.1,01Jan2023_00h00m00s_7_hosts,0.0.0.0,1234,internal,0,981e52b4-175b-11f1-b65c-c25d5799b044,10.10.10.1
```

* `2023-01-01T00:00:00Z` - event timestamp
* `demo-watcher` - name of watcher
* `metric` - event name: `host`, `network`, `metric`
* `192.168.13.0/24` - event object. Watcher detected an event related to `192.168.13.0/24` subnet
* `changed` - event status: `down`, `up`, `changed`
* `10` - old cost
* `12` - new cost
* `10.10.10.1` - event detected by this node.
* `01Jan2023_00h00m00s_7_hosts` - name of graph in Topolograph dashboard
* `0.0.0.0` - OSPF area ID
* `1234` - AS number where OSPF is working
* `internal` - type of network: `internal` or `external`
* `0` - subtype of network: type-1, type-2 or 0 for internal subnets
* `981e52b4-175b-11f1-b65c-c25d5799b044` - session ID, the same session till next LSDB update
* `10.10.10.1` - source ID
*Summary: `10.10.10.1` detected that metric of `192.168.13.0/24` internal stub network changed from `10` to `12` at `2023-01-01T00:00:00Z` in area 0*

##### Logs sample 3 (TE)
```
2024-12-29T13:20:50.398Z,ospfwatcher-demo,temetric,10.10.10.6,changed,0_17_19_20_21_22_26_29_30,1000000000,1000000000,1000000008_1000000016_1000000024_1000000032_1000000040_1000000048_1000000056,11223344,10.10.10.3,2024-07-28T18:03:05Z,0.0.0.0,12345,192.168.36.3,192.168.36.6,981e52b4-175b-11f1-b65c-c25d5799b044,10.10.10.1
```
* `temetric` - event name for TE attribute change
* `10.10.10.6` - event object (neighbor/link ID)
* `0_17_19_20_21_22_26_29_30` - admin group bit indices
* `1000000000` - Maximum Link Bandwidth (bits/sec)
* `1000000000` - Maximum Reservable Link Bandwidth (bits/sec)
* `1000000008_...` - Unreserved Bandwidth for priority 0..7 (bits/sec)
* `11223344` - Traffic Engineering Default Metric
* `10.10.10.3` - event detected by (advertising router)
* `192.168.36.3`, `192.168.36.6` - local and remote interface IP addresses
* `981e52b4-175b-11f1-b65c-c25d5799b044` - session ID, the same session till next LSDB update
* `10.10.10.1` - source ID
```


Note:
`prepare.sh` creates `watcher/logs/` and the log file owned by the user that runs the lab.
