# OSPF Topology Watcher
OSPF Watcher is a monitoring tool of OSPF topology changes for network engineers. It works via passively listening to OSPF control plane messages through a specially established OSPF adjacency between OSPF Watcher and one of the network device. The tool logs OSPF events and/or export by Logstash to **Elastic Stack (ELK)**, **Zabbix**, **WebHooks** and **Topolograph** monitoring dashboard for keeping the history of events, alerting, instant notification. Components of the solution are wrapped into containers, so it can be increadebly fast to start it. The only thing is needed to configure manually - is GRE tunnel setup on the Linux host.  
## Logged topology changes:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appeared/disappeared from the topology

## Architecture
![](docs/ospfwatcher_plus_topolograph_architecture.png)  
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
![](https://github.com/Vadims06/ospfwatcher/blob/774ffe06131e932bd0d87b430010523d942a2342/docs/cost-changes-raw-logs.png)

Logs if OSPF adjacency was Up/Down or any networks appeared/disappeared.  
![](https://github.com/Vadims06/ospfwatcher/blob/774ffe06131e932bd0d87b430010523d942a2342/docs/host-updown-raw-logs.png)

#### Topolograph OSPF Monitoring. New subnet event shows where the subnet appeared  
![](https://github.com/Vadims06/topolograph/blob/56861d2d72399c92a6858346cd42171cbd6da4c7/docs/release-notes/v2.27/ospf_monitoring_new_subnet.PNG)  
  
  
#### Topolograph OSPF Monitoring. Filter any subnet-related events, select Change metric event
new and old metric is shown
![](https://github.com/Vadims06/topolograph/blob/56861d2d72399c92a6858346cd42171cbd6da4c7/docs/release-notes/v2.27/ospf_monitoring_change_metric.PNG) 

#### Topolograph OSPF Monitoring. up/down link events
Red timelines show link (~adjacency) down events, green one - up link (~adjacency).  
Timeline `10.1.1.2-10.1.1.3` has been selected.
![](https://github.com/Vadims06/topolograph/blob/56861d2d72399c92a6858346cd42171cbd6da4c7/docs/release-notes/v2.27/ospf_monitoring_down_link.PNG)

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
![](https://github.com/Vadims06/ospfwatcher/blob/4596d4dfe368bf3500ab1cf64236946bbe4e45fb/docs/slack/slack_notification.PNG)

## How to setup
1. Choose a Linux host with Docker installed
2. Setup Topolograph (optionally)  
It's needed for visual network events check on Topolograph UI. Skip if you don't want it. 
* launch your own Topolograph on docker using [topolograph-docker](https://github.com/Vadims06/topolograph-docker) or make sure you have a connection to the public https://topolograph.com
* create a user for API authentication using Local Registration form on the site, add your IP address in `API/Authorised source IP ranges` on the site and write down the following variables
> **Note**  
> * `TOPOLOGRAPH_HOST` - *set the IP address of your host, where the docker is hosted (if you run all demo on a single machine), do not put `localhost`, because ELK, Topolograph and OSPF Watcher run in their private network space*
> * `TOPOLOGRAPH_PORT` - by default `8080`
> * `TOPOLOGRAPH_WEB_API_USERNAME_EMAIL` - by default `ospf@topolograph.com` or put your recently created user
> * `TOPOLOGRAPH_WEB_API_PASSWORD` - by default `ospf`
> * `TEST_MODE` - if mode is `True`, a demo OSPF events from static file will be uploaded, not from FRR      
3. Setup ELK (optionally)  
It's needed for visual network events check on Elastic search UI. Skip if you don't want it. 
* if you already have ELK instance running, so just remember `ELASTIC_IP` for filling env file later and uncomment Elastic config here `ospfwatcher/logstash/pipeline/logstash.conf`. Currently additional manual configuration is needed for creation Index Templates, because the demo script doesn't accept the certificate of ELK. It's needed to have one in case of security setting enabled. Required mapping for the Index Template is in `ospfwatcher/logstash/index_template/create.py`. Fill free to edit such a script for your needs.
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
sudo docker run -it --rm --user $UID -v ./:/home/watcher/watcher/ -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro vadims06/ospf-watcher:latest python3 ./client.py --action add_watcher
```   
The script will create:
1. a folder under `watcher` folder with FRR configuration under `router` folder
2. a containerlab configuration file with network settings
3. an individual watcher log file in `watcher` folder.  

To stop OSPF routes from being installed in the host's routing table, we the following policy has been applied on the watcher:
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
7. Start log export to Topolograph and/or ELK
```
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

## Troubleshooting
#### OSPF Watcher <-> Network device connection
`ospf-watcher:v1.7` has `diagnostic` method in `client.py`, which can check packets (tcpdump) from FRR, Iptables settings for a network device. 
```
sudo docker run -it --rm -v ./:/home/watcher/watcher/ --cap-add=NET_ADMIN -u root --network host vadims06/ospf-watcher:v1.7 python3 ./client.py --action diagnostic --watcher_num <num>
```   
#### OSPF Watcher <-> Dashboard page
This is a quick set of checks in case of absence of events on OSPF Monitoring page. OSPF Watcher consists of three services: OSPFd/FRR [1] -> Watcher [2] -> Logstash [3] -> Topolograph & ELK & Zabbix & WebHooks.
1. Check if FRR tracks OSPF changes, run the following command:  
```
docker exec -it quagga cat /var/log/quagga/ospfd.log
```   
you should see logs similar to [this](https://github.com/Vadims06/ospfwatcher/blob/d8366508abc51627c7f9a2ce6e47b7f23e420f1e/watcher/tests/test25.txt)   
2. Check if Watcher parses changes:   
```
docker exec -it watcher cat /home/watcher/watcher/logs/watcher.log
```
You should see tracked changes of your network, i.e. here we see that `10.0.0.0/29` network went up at `2023-10-27T07:50:24Z` on `10.10.1.4` router.   
```
2023-10-27T07:50:24Z,demo-watcher,network,10.0.0.0/29,up,10.10.1.4,28Oct2023_01h10m02s_7_hosts_ospfwatcher
```
3. Check that messages are sent:  
    1. Uncomment `DEBUG_BOOL="True"` in `.env` and check logs `docker logs logstash` and do:
        - wait for the next event in your network
        - change a cost of you stub network, return it back and see this event in this logs
        - simulate network changes   
            ```
            docker exec -it watcher /bin/bash
            echo "2023-10-27T07:50:24Z,demo-watcher,network,10.0.0.0/29,up,10.10.1.4,28Oct2023_01h10m02s_7_hosts_ospfwatcher" >> /home/watcher/watcher/logs/watcher.log
            ```    
    2. Connect to mongoDB and check logs:
    ```
    docker exec -it mongo /bin/bash
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

 ### Minimum Logstash version
 7.17.21, this version includes bug fix of [issues_281](https://github.com/logstash-plugins/logstash-input-file/issues/281), [issues_5115](https://github.com/elastic/logstash/issues/5115)  

 ### License
 The functionality was tested using Basic ELK license.  
