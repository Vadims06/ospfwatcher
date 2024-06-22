# IS-IS watcher. Tracking IS-IS topology changes in Real-Time

![IS-IS watcher containerlab](container_lab.drawio.png)
This lab consists of 6 FRR routers and a single IS-IS Watcher. Each router is pre-configured for being in IS-IS domain with different network type. Topology changes are printed in a text file only (which is enough for testing), for getting logs exported to ELK or Topolograph (to see network changes on a map) start `docker-compose` files and follow instructions on main README.

### IS-IS Topology Watcher
IS-IS Watcher is a monitoring tool of IS-IS topology changes for network engineers. It works via passively listening to IS-IS control plane messages through a specially established IS-IS adjacency between IS-IS Watcher and one of the network device. The tool logs IS-IS events into a static file, which can be exported by Logstash to **Elastic Stack (ELK)**, **Zabbix**, **WebHooks** and **Topolograph** monitoring dashboard for keeping the history of events, alerting, instant notification.

#### Detected network events:
* IS-IS neighbor adjacency Up/Down
* IS-IS link cost changes
* IS-IS networks appearance/disappearance from the topology

### Supported IS-IS TLV 
| TLV name                         | TLV |
|----------------------------------|-----|
| IS Reachability                  | 2   |
| Extended IS Reachability   (new) | 22  |
| IPv4 Internal Reachability (old) | 128 |
| IPv4 External Reachability (old) | 130 |
| Extended IPv4 Reachability (new) | 135 |
| IPv6 Reachability                | 236 |  

## Quickstart

1. [Install](https://containerlab.srlinux.dev/install/) containerlab.
2. Run the script to prepare environment:

    ```
    ./prepare.sh
    ```

3. Start the lab
    ```
    sudo clab deploy --topo frr01.clab.yml
    ```

4. Start watching logs
    ```
    sudo tail -f watcher/watcher.log
    ```

5. Change IS-IS settings on lab' routers. Connect to a router
    ```
    sudo docker exec -it clab-frr01-router2 vtysh
    ```

### IS-IS Watcher logs location
Available under `watcher` folder. To see them:
```
sudo tail -f watcher/watcher.log
```

### Logs sample 1  
```
2023-01-01T00:00:00Z,demo-watcher,1,host,0200.1001.0002,down,0200.1001.0003,01Jan2023_00h00m00s_7_hosts
```

* `2023-01-01T00:00:00Z` - event timestamp
* `demo-watcher` - name of watcher
* `1` - IS-IS level
* `host` - event name: `host`, `network`, `metric`
* `0200.1001.0002` - event object. Watcher detected an event related to `0200.1001.0002` host
* `down` - event status: `down`, `up`, `changed`
* `0200.1001.0003` - event detected by this node.
* `01Jan2023_00h00m00s_7_hosts` - name of graph in Topolograph dashboard
*Summary: `0200.1001.0003` detected that `0200.1001.0002` host went down at `2023-01-01T00:00:00Z` in IS-IS level 1*

### Logs sample 2  
```
2023-01-01T00:00:00Z,isis-watcher,2,metric,4ffe::192:168:23:2/127,changed,old_cost:10,new_cost:12,0200.1001.0002,stub,0200.1001.0002,01Jan2023_00h00m00s_7_hosts
```

* `2023-01-01T00:00:00Z` - event timestamp
* `isis-watcher` - name of watcher
* `2` - IS-IS level
* `metric` - event name: `host`, `network`, `metric`
* `4ffe::192:168:23:2/127` - event object. Watcher detected an event related to 4ffe::192:168:23:2/127` subnet
* `changed` - event status: `down`, `up`, `changed`
* `10` - old cost
* `12` - new cost
* `0200.1001.0002` - event detected by this node.
* `stub` - subnet type
* `0200.1001.0002` - since it's a stub network it has router id of terminated node.
* `01Jan2023_00h00m00s_7_hosts` - name of graph in Topolograph dashboard
*Summary: `0200.1001.0002` detected that metric of `4ffe::192:168:23:2/127` stub network changed from `10` to `12` at `2023-01-01T00:00:00Z` in IS-IS level 2*


Note:
log file should have `systemd-network:systemd-journal` ownership

> **Note**  
> This lab is based on simple FRR for building topology based on frr routers, more information about it is available here: https://www.brianlinkletter.com/2021/05/use-containerlab-to-emulate-open-source-routers/

