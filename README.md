# OSPF Topology Watcher
OSPF Watcher is a monitoring tool of OSPF topology changes for network engineers. It works via passively listening to OSPF control plane messages through a specially established OSPF adjacency between OSPF Watcher and one of the network device. The tool logs OSPF events and/or export by Logstash to **Elastic Stack (ELK)**, **Zabbix**, **WebHooks** and **Topolograph** monitoring dashboard for keeping the history of events, alerting, instant notification. Components of the solution are wrapped into containers, so it can be increadebly fast to start it. The only thing is needed to configure manually - is GRE tunnel setup on the Linux host. 
> **Note**  
> Upvote in [issues/12](https://github.com/Vadims06/ospfwatcher/issues/12) if you are interested in tracking OSPF topology changes via BGP-LS.     
## Logged topology changes:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appeared/disappeared from the topology

## Architecture
![](docs/ospfwatcher_plus_topolograph_architecture_v2.png)  
Each Watcher instance maintains all routes and updates within an isolated network namespace. This isolation ensures efficient monitoring without interference and prevent route leaks.

> **Note**  
> ospfwatcher:v1.1 is compatible with [topolograph:v2.7](https://github.com/Vadims06/topolograph/releases/tag/v2.27), it means that OSPF network changes can be shown on the network graph.
### Functional Role
![](docs/functional-watcher-role.png)
## Demo
Click on the image in order zoom it.  
![](https://github.com/Vadims06/ospfwatcher/blob/ada2ca86df171ec5f1b550da821f0a8ca1cb1df4/docs/ospf-watcher-demo.gif)

## Discovering OSPF logs in Kibana. Examples
OSPF cost changes on links  
![](docs/cost-changes-raw-logs.png)

Logs if OSPF adjacency was Up/Down or any networks appeared/disappeared.  
![](docs/host-updown-raw-logs.png)

#### Topolograph OSPF Monitoring. New subnet event shows where the subnet appeared  
![](docs/ospf_monitoring_new_subnet.PNG)  
  
  
#### Topolograph OSPF Monitoring. Filter any subnet-related events, select Change metric event
new and old metric is shown
![](docs/ospf_monitoring_change_metric.PNG) 

#### Topolograph OSPF Monitoring. up/down link events
Red timelines show link (~adjacency) down events, green one - up link (~adjacency).  
Timeline `10.1.1.2-10.1.1.3` has been selected.
![](docs/ospf_monitoring_down_link.PNG)

## OSPF topology change notification/alarming via Zabbix. Examples
Zabbix's dashboard with active OSPF alarms detected by OSPFWatcher  
![](https://github.com/Vadims06/ospfwatcher/blob/cc690cff7cb9a99543b4a4c5163db54284e8f888/docs/zabbix-ui/zabbix_dashboard_with_all_alarms.png)
#### Zabbix OSPF neighbor up/down alarm
This alarm tracks all new OSPF adjacencies or when device loses its OSPF neighbor
![](https://github.com/Vadims06/ospfwatcher/blob/cc690cff7cb9a99543b4a4c5163db54284e8f888/docs/zabbix-ui/zabbix_ospf_neighbor_up_log_latest_data.png)
#### Zabbix OSPF Cost changed on transit links
Transit links are all links between active OSPF neighbors. If cost on a link was changed it might affect all actual/shortest paths traffic follows 
![](https://github.com/Vadims06/ospfwatcher/blob/cc690cff7cb9a99543b4a4c5163db54284e8f888/docs/zabbix-ui/zabbix_ospf_link_cost_change_log_latest_data.png)
#### Zabbix alert if OSPF network was stopped announcing from node
If a subnet was removed from OSPF node (the node withdrew it from the announcement) it means the network from this node became unavailable for others, this event will be logged too.
![](https://github.com/Vadims06/ospfwatcher/blob/cc690cff7cb9a99543b4a4c5163db54284e8f888/docs/zabbix-ui/zabbix_ospf_network_up_log_latest_data.png)

#### Slack notification
HTTP POST messages can be easily accepted by messengers, which allows to get instant notifications of OSPF topology changes:
![](docs/slack/slack_notification.PNG)

## Quick lab
#### Containerlab
Here is a lab for tracking OSPF topology changes placed here **containerlab/frr01**. Watcher logs:  
![](docs/ospfwatcher_containerlab.png)    
OSPF topology changes are printed by Watcher in a text file only.
```
./containerlab/frr01/prepare.sh
sudo clab deploy --topo ./containerlab/frr01/frr01.clab.yml
```   

## How to connect OSPF watcher to real network  
Table below shows different options of possible setups, starting from the bare minimum in case of running Containerlab for testing and ending with maximum setup size with Watcher, Topolograph and ELK. The following setup describes setup **№2**. 
| № | Deployment size                                                                            | Number of compose files | Text file logs | View changes on network map | Zabbix/HTTP/Messengers notification | Searching events by any field any time |
|---|--------------------------------------------------------------------------------------------|-------------------------|----------------|-----------------------------|-------------------------------------|----------------------------------------|
| 1 | Bare minimum. Containerlab                                                                 |            0            |        +       |              -              |                  -                  |                    -                   |
| 2 | 1. Local Topolograph  <br>2. local compose file with ELK **disabled** (commented) |            2            |        +       |              +              |                  +                  |                    -                   |
| 3 | 1. Local Topolograph  <br>2. local compose file with ELK **enabled**              |            3            |        +       |              +              |                  +                  |                    +                   |

#### Setup №2. Text logs + timeline of network changes on Topolograph 
1. Choose a Linux host with Docker installed
2. Setup Topolograph
It's needed for visual network events check on Topolograph UI. Skip if you don't want it. 
* launch your own Topolograph on docker using [topolograph-docker](https://github.com/Vadims06/topolograph-docker) or make sure you have a connection to the public https://topolograph.com
* create a user for API authentication using `Local Registration` form on the Topolograph page, add your IP address in `API/Authorised source IP ranges`.
Set variables in `.env` file:    

> **Note**  
> * `TOPOLOGRAPH_HOST` - *set the IP address of your host, where the docker is hosted (if you run all demo on a single machine), do not put `localhost`, because ELK, Topolograph and OSPF Watcher run in their private network space*
> * `TOPOLOGRAPH_PORT` - by default `8080`
> * `TOPOLOGRAPH_WEB_API_USERNAME_EMAIL` - by default `ospf@topolograph.com` or put your recently created user
> * `TOPOLOGRAPH_WEB_API_PASSWORD` - by default `ospf`
> * `TEST_MODE` - if mode is `True`, a demo OSPF events from static file will be uploaded, not from FRR      
3. Setup ELK (skip it, it's only needed for setup № 3)  
* if you already have ELK instance running, fill `ELASTIC_IP` in env file and uncomment Elastic config here `ospfwatcher/logstash/pipeline/logstash.conf`. Currently additional manual configuration is needed for Index Templates creation, because `create.py` script doesn't accept the certificate of ELK. It's needed to have one in case of security setting enabled. Required mapping for the Index Template is in `ospfwatcher/logstash/index_template/create.py`.
To create Index Templates, run:
```
sudo docker run -it --rm --env-file=./.env -v ./logstash/index_template/create.py:/home/watcher/watcher/create.py vadims06/ospf-watcher:latest python3 ./create.py
```   
* if not - boot up a new ELK from [docker-elk](https://github.com/deviantony/docker-elk) compose. For demo purporse set license of ELK as basic and turn off security. The setting are in docker-elk/elasticsearch/config/elasticsearch.yml  
```
xpack.license.self_generated.type: basic
xpack.security.enabled: false
```  
> **Note about having Elastic config commented**
    > When the Elastic output plugin fails to connect to the ELK host, it blocks all other outputs and ignores "EXPORT_TO_ELASTICSEARCH_BOOL" value from env file. Regardless of EXPORT_TO_ELASTICSEARCH_BOOL being False, it tries to connect to Elastic host. The solution - uncomment this portion of config in case of having running ELK.

4. Setup OSPF Watcher
```bash
git clone https://github.com/Vadims06/ospfwatcher.git
cd ospfwatcher
```
Generate configuration files  
`vadims06/ospf-watcher:v1.7` includes a client for generating configurations for each Watcher for each OSPF area. To generate individual settings - run the client with `--action add_watcher`   
```
sudo docker run -it --rm --user $UID -v ./:/home/watcher/watcher/ -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro vadims06/ospf-watcher:v2.0.8 python3 ./client.py --action add_watcher
```   
Output:   
```
+---------------------------+
|  Watcher Host             |                       +-------------------+
|  +------------+           |                       | Network device    |
|  | netns FRR  |           |                       |                   |
|  |            Tunnel [4]  |                       | Tunnel [4]        |
|  |  gre1   [3]TunnelIP----+-----------------------+[2]TunnelIP        |
|  |  eth1------+-vhost1    |       +-----+         | OSPF area num [5]|
|  |            | Host IP[6]+-------+ LAN |--------[1]Device IP         |
|  |            |           |       +-----+         |                   |
|  +------------+           |                       |                   |
|                           |                       +-------------------+
+---------------------------+
[1]Network device IP [x.x.x.x]: 
```
The script will create:
1. a folder under `watcher` folder with FRR configuration under `router` folder
2. a containerlab configuration file with network settings
3. an individual watcher log file in `watcher` folder.  

OSPF routes of each Watcher instance stay isolated in watcher's network namespace. To stop OSPF routes from being installed even in the watcher's network namespace, we the following policy has been applied on the watcher:
```bash
# quagga/config/ospfd.conf
route-map TO_KERNEL deny 200
exit
!
ip protocol ospf route-map TO_KERNEL
```

5. Start OSPF Watcher  
[Install](https://containerlab.srlinux.dev/install/) containerlab
To start the watcher run the following command. `clab deploy` is like a `docker compose up -d` command   
```
sudo clab deploy --topo watcher/watcher1-tun1025/config.yml
```
It will create:
* Individual network namespace for Watcher and FRR
* A pair of tap interfaces to connect the watcher to Linux host
* GRE tunnel in Watcher's namespace
* NAT settings for GRE traffic
* FRR & Watcher instance

6. Setup GRE tunnel from the network device to the host. An example for Cisco
> **Note**  
> You can skip this step and run ospfwatcher in `test_mode`, so test LSDB from the file will be taken and test changes (loss of adjacency and change of OSPF metric) will be posted in ELK  

```bash
interface gigabitether0/1
ip address <GRE tunnel ip address>
tunnel mode gre
tunnel source <router-ip>
tunnel destination <host-ip>
ip ospf network type point-to-point
```
Set GRE tunnel network where <GRE tunnel ip address> is placed to `quagga/config/ospfd.conf`  

Check OSPF neighbor, if there is no OSPF adjacency between network device and OSPF Watcher, check troubleshooting `OSPF Watcher <-> Network device connection` section below (to run diagnostic script).  
7. Start log export to Topolograph and/or ELK (optionally if you configured Step 2 or 3)  
```
docker-compose build
docker-compose up -d
```

 ## Kibana settings
 1. **Index Templates**  have already been created. It's needed to check that logs are received by ELK via `Stack Management/ Kibana/ Stack Management/ Index Management`. `watcher-costs-changes` and `watcher-updown-events` should be in a list.  
  ![](https://github.com/Vadims06/ospfwatcher/blob/57a6a82eafe10cedcbf3f3e70ddf69397401f1ca/docs/kibana_index_template.png)  
 2. Create **Index Pattern** for old ELK `Stack Management/ Kibana/ Stack Management/ Index Pattern` -> `Create index pattern` or **Data View** in new ELK `Stack Management/ Kibana/ Stack Management/ Data Views` and specify `watcher-updown-events` as Index pattern name -> Next -> choose `watcher_time` as timestamp.  
 ![](https://github.com/Vadims06/ospfwatcher/blob/57a6a82eafe10cedcbf3f3e70ddf69397401f1ca/docs/kibana_data_view.png)  
 Repeat the step for creation `watcher-costs-changes`  
 Because the connection between Watcher (with Logstash) can be lost, but watcher continues to log all topology changes with the correct time. When the connection is repaired, all logs will be added 
 to ELK and you can check the time of the incident. If you choose `@timestamp` - the time of all logs will be the time of their addition to ELK.  
 
 ## Browse your topology changes logs
 Your logs are here http://localhost:5601/ -> `Analytics/Discover` `watcher-updown-events`. 
 
 ## Zabbix settings
 Zabbix settings are available here ```/docs/zabbix-ui```. There are 4 hosts and items (host and item inside each host has the same names) are required:
 * ospf_neighbor_up_down
 * ospf_network_up_down
 * ospf_link_cost_change
 * ospf_stub_network_cost_change

 ## WebHook setting
1. Create a Slack app
2. Enable Incoming Webhooks
3. Create an Incoming Webhook (generates URL)
4. Uncomment `EXPORT_TO_WEBHOOK_URL_BOOL` in `.env`, set the URL to `WEBHOOK_URL`

##### Logs sample 1  
```
2023-01-01T00:00:00Z,demo-watcher,host10.10.10.4,down,10.10.10.5,01Jan2023_00h00m00s_7_hosts
```

* `2023-01-01T00:00:00Z` - event timestamp
* `demo-watcher` - name of watcher
* `host` - event name: `host`, `network`, `metric`
* `10.10.10.4` - event object. Watcher detected an event related to `10.10.10.4` host
* `down` - event status: `down`, `up`, `changed`
* `10.10.10.5` - event detected by this node.
* `01Jan2023_00h00m00s_7_hosts` - name of graph in Topolograph dashboard
*Summary: `10.10.10.5` detected that `10.10.10.4` host went down at `2023-01-01T00:00:00Z`*

##### Logs sample 2  
```
2023-01-01T00:00:00Z,demo-watcher,network,192.168.13.0/24,changed,old_cost:10,new_cost:12,10.10.10.1,01Jan2023_00h00m00s_7_hosts,0.0.0.0,1234,internal,0
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
*Summary: `10.10.10.1` detected that metric of `192.168.13.0/24` internal stub network changed from `10` to `12` at `2023-01-01T00:00:00Z` in area 0*

## Troubleshooting
##### Symptoms
Networks changes are not tracked. Log file `./watcher/logs/watcher...log` is empty.

##### Steps:
1. Run diagnostic script. It will check **OSPF Watcher** <-> **Network device** connection (iptables, packets from FRR/network device)

    ```
    sudo docker run -it --rm -v ./:/home/watcher/watcher/ --cap-add=NET_ADMIN -u root --network host vadims06/ospf-watcher:latest python3 ./client.py --action diagnostic --watcher_num <num>
    ``` 
2. Login on FRR.

    ```
    sudo docker exec -it watcher#-gre#-ospf-router vtysh
    ```
    `show ip ospf neighbor` should show network device as a neighbor in the output.

##### Symptoms
Dashboard page is blank. Events are not present on OSPF Monitoring page.
##### Steps:
OSPF Watcher consists of three services: OSPFd/FRR [1] -> Watcher [2] -> Logstash [3] -> Topolograph & ELK & Zabbix & WebHooks. Let's start each component one by one.
1. Check if FRR tracks OSPF changes in `./watcher/logs/watcher...log` file (previous case)   
You should see tracked changes of your network, i.e. here we see that `10.0.0.0/29` network went up at `2023-10-27T07:50:24Z` on `10.10.1.4` router.   
    ```
    2024-07-22T20:24:08Z,watcher-local,network,8.8.0.60/30,changed,old_cost:12,new_cost:-1,10.10.10.5,01Jan2023_00h00m00s_7_hosts,0.0.0.0,65001,external,1
    ```
2. Check that logstash container from [docker-compose.yml](./docker-compose.yml) is running via `docker ps` command.  

    1. Uncomment `DEBUG_BOOL="True"` in `.env` and start continuous logs `docker logs -f logstash`.
    2. Copy and paste the log from the first step in watcher's log file  `./watcher/logs/watcher#-gre#-ospf.ospf.log`. `docker logs -f logstash` should print the output. If not - check logstash container.
  
3. Check if logs are in Topolograph's DB. Connect to mongoDB and run:
    ```
    docker exec -it mongodb /bin/bash
    ```  
    Inside container (change):  
    ```
    mongo mongodb://$MONGO_INITDB_ROOT_USERNAME:$MONGO_INITDB_ROOT_PASSWORD@mongodb:27017/admin?gssapiServiceName=mongodb
    use admins
    ```
    Check the last two/N records in adjacency changes (`adj_change`) or cost changes (`cost_change`)
    ```
    db.adj_change.find({}).sort({_id: -1}).limit(2)
    db.cost_change.find({}).sort({_id: -1}).limit(2)
    ```
    > **Note**  
    > If you see a single event in `docker logs logstash` it means that mongoDB output is blocked, check if you have a connection to MongoDB `docker exec -it logstash curl -v mongodb:27017`   

##### Development   
Logstach pipeline development.
Start logstash container
```
[ospf-watcher]# docker run -it --rm --network=topolograph_backend --env-file=./.env -v ./logstash/pipeline:/usr/share/logstash/pipeline -v ./logstash/config:/usr/share/logstash/config ospfwatcher_watcher:latest /bin/bash
```
Inside container run this command:
```
bin/logstash -e 'input { stdin { } } filter { dissect { mapping => { "message" => "%{watcher_time},%{watcher_name},%{event_name},%{event_object},%{event_status},old_cost:%{old_cost},new_cost:%{new_cost},%{event_detected_by},%{subnet_type},%{shared_subnet_remote_neighbors_ids},%{graph_time}" }} mutate { update => { "[@metadata][mongo_collection_name]" => "adj_change" }} } output { stdout { codec  => rubydebug {metadata => true}} }'
```
It will expect an input from CLI, so copy and paste this line of log
```
2023-01-01T00:00:00Z,demo-watcher,metric,10.1.14.0/24,changed,old_cost:10,new_cost:123,10.1.1.4,stub,10.1.1.4,01Jan2023_00h00m00s_7_hosts
```
The output should be:
```
[INFO ] 2024-05-13 21:15:25.462 [[main]-pipeline-manager] javapipeline - Pipeline started {"pipeline.id"=>"main"}
The stdin plugin is now waiting for input:
[INFO ] 2024-05-13 21:15:25.477 [Agent thread] agent - Pipelines running {:count=>1, :running_pipelines=>[:main], :non_running_pipelines=>[]}
2023-01-01T00:00:00Z,demo-watcher,metric,10.1.14.0/24,changed,old_cost:10,new_cost:123,10.1.1.4,stub,10.1.1.4,01Jan2023_00h00m00s_7_hosts
{
                            "graph_time" => "01Jan2023_00h00m00s_7_hosts",
                     "event_detected_by" => "10.1.1.4",
                           "subnet_type" => "stub",
                               "message" => "2023-01-01T00:00:00Z,demo-watcher,metric,10.1.14.0/24,changed,old_cost:10,new_cost:123,10.1.1.4,stub,10.1.1.4,01Jan2023_00h00m00s_7_hosts",
                          "watcher_name" => "demo-watcher",
                          "watcher_time" => "2023-01-01T00:00:00Z",
                            "@timestamp" => 2024-05-13T21:15:50.628Z,
                              "old_cost" => "10",
                              "@version" => "1",
                                  "host" => "ba8ff3ab31f8",
                            "event_name" => "metric",
                              "new_cost" => "123",
    "shared_subnet_remote_neighbors_ids" => "10.1.1.4",
                          "event_object" => "10.1.14.0/24",
                          "event_status" => "changed"
}
```
### Minimum Logstash version
 7.17.21, this version includes bug fix of [issues_281](https://github.com/logstash-plugins/logstash-input-file/issues/281), [issues_5115](https://github.com/elastic/logstash/issues/5115)  

### Topolograph suite
* OSPF Watcher [link](https://github.com/Vadims06/ospfwatcher)
* IS-IS Watcher [link](https://github.com/Vadims06/isiswatcher)
* Topolograph [link](https://github.com/Vadims06/topolograph)
* Topolograph in docker [link](https://github.com/Vadims06/topolograph-docker)

### Community & feedback
* https://t.me/topolograph
* admin at topolograph.com

### License
 GPL-3.0 license
 Elastic search was used with Basic ELK license.  
