# OSPF Topology Watcher
OSPF Watcher is a monitoring tool of OSPF topology changes for network engineers. It works via passively listening to OSPF control plane messages through a specially established OSPF adjacency between OSPF Watcher and one of the network device. The tool logs OSPF events and/or export by Logstash to **Elastic Stack (ELK)**, **Zabbix**, **WebHooks** and **Topolograph** monitoring dashboard for keeping the history of events, alerting, instant notification. Components of the solution are wrapped into containers, so it can be increadebly fast to start it. The only thing is needed to configure manually - is GRE tunnel setup on the Linux host.  
## Logged topology changes:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appeared/disappeared from the topology

## Architecture
![](https://github.com/Vadims06/ospfwatcher/blob/23536a5f7d296cbced4dce95c8bdee43dd93821f/docs/ospfwatcher_plus_topolograph_architecture.png)  
The Quagga container has `network_mode=host` so it sees the GRE tunnel, which is configured by Admin on the Linux Host.  
Integration with **Zabbix** was added in *ospfwatcher:v1.4* for allerting/notification of OSPF topology changes.   
> **Note**  
> ospfwatcher:v1.1 is compatible with [topolograph:v2.7](https://github.com/Vadims06/topolograph/releases/tag/v2.27), it means that OSPF network changes can be shown on the network graph.
### Functional Role
![](https://github.com/Vadims06/ospfwatcher/blob/247bb4d330de762cfc4c3fd67135e5740ba8403c/docs/functional-watcher-role.png)
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
2. Setup Topolograph:  
* launch your own Topolograph on docker using [topolograph-docker](https://github.com/Vadims06/topolograph-docker) or make sure you have a connection to the public https://topolograph.com  
> **Note**  
> In case of using external topolograph.com create a user for API authentication using Local Registration form on the site, add your IP address in `API/Authorised source IP ranges` on the site and write down the following variables (in case of using Docker version - left default variables and go to the next step):    
> * `TOPOLOGRAPH_HOST`
> * `TOPOLOGRAPH_PORT`
> * `TOPOLOGRAPH_USER_LOGIN`
> * `TOPOLOGRAPH_USER_PASS`         
3. Setup ELK  
* if you already have ELK instance running, so just remember `ELASTIC_IP` for filling env file later. Currently additional manual configuration is needed for creation Index Templates, because the demo script doesn't accept the certificate of ELK. It's needed to have one in case of security setting enabled. Required mapping for the Index Template is in `ospfwatcher/logstash/index_template/create.py`. Fill free to edit such a script for your needs.
* if not - boot up a new ELK from [docker-elk](https://github.com/deviantony/docker-elk) compose. For demo purporse set license of ELK as basic and turn off security. The setting are in docker-elk/elasticsearch/config/elasticsearch.yml  
```
xpack.license.self_generated.type: basic
xpack.security.enabled: false
```  

4. Setup GRE tunnel from the host to a network device  
It's needed to have minimum one GRE tunnel to an area, which is needed to be monitored. If OSPF domain has multiple areas, setup one GRE into each area. It's a restriction of OSPF architecture to knows about new/old adjancency or link cost changes via LSA1/LSA2 per area basis only. So Quagga host in OSPF Watcher should know about all subnets in all areas (which we want to monitor) and in order to isolate subnets from each other apply the policy to reject OSPF routers from installing them into the host's routing table. An example of such a policy is below: 
```bash
# quagga/config/ospfd.conf
route-map TO_KERNEL deny 200
exit
!
ip protocol ospf route-map TO_KERNEL
```
> **Note**  
> You can skip this step and run ospfwatcher in `test_mode`, so test LSDB from the file will be taken and test changes (loss of adjancency and change of OSPF metric) will be posted in ELK  
```bash
sudo modprobe ip_gre
sudo ip tunnel add tun0 mode gre remote <router-ip> local <host-ip> dev eth0 ttl 255
sudo ip address add <GRE tunnel ip address> dev tun0
sudo ip link set tun0 up
```
5. Setup GRE tunnel from the network device to the host. An example for Cisco
> **Note**  
> You can skip this step and run ospfwatcher in `test_mode`, so test LSDB from the file will be taken and test changes (loss of adjancency and change of OSPF metric) will be posted in ELK  

```bash
interface gigabitether0/1
ip address <GRE tunnel ip address>
tunnel mode gre
tunnel source <router-ip>
tunnel destination <host-ip>
ip ospf network type point-to-point
```
Set GRE tunnel network where <GRE tunnel ip address> is placed to `quagga/config/ospfd.conf`  

# How to start
```bash
git clone https://github.com/Vadims06/ospfwatcher.git
cd ospfwatcher
```
Set variables in `.env` file:    
 * ELASTIC_IP=192.168.0.10 - *set the IP address of your host, where the docker is hosted (if you run all demo on a single machine), do not put `localhost`, because ELK, Topolograph and OSPF Watcher run in their private network space*
 * TOPOLOGRAPH_HOST=192.168.0.10 - *same logic here*
 * TEST_MODE='True' - if mode is `test`, a demo LSDB from the file will be taken, not from Quagga  

Default values for your information:  
 * ELASTIC_PORT=9200
 * ELASTIC_USER_LOGIN=elastic
 * ELASTIC_USER_PASS=changeme
 * TOPOLOGRAPH_PORT=8080
 * TOPOLOGRAPH_WEB_API_USERNAME_EMAIL=ospf@topolograph.com
 * TOPOLOGRAPH_WEB_API_PASSWORD=ospf  

Start docker-compose  
```bash
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

 ### Minimum Logstash version
 7.17.0, this version includes bug fix of [issues_281](https://github.com/logstash-plugins/logstash-input-file/issues/281), [issues_5115](https://github.com/elastic/logstash/issues/5115)  

 ### License
 The functionality was tested using Basic ELK license.  
