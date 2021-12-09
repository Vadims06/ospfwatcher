# OSPF Topology Watcher
OSPF Topology Watcher is like a Git for developers - it helps to track OSPF topology changes and shows it on the history diagram. Changes are exported by Logstash to Elastic Stack (ELK). Components of the solution are wrapped into containers, so it can be increadebly fast to start it. The only thing is needed to configure manually - is GRE tunnel setup on the Linux host.  
Logged topology changes:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appeared/disappeared from the topology

## Architecture
![](https://github.com/Vadims06/ospfwatcher/blob/f218b754ac7b543ffe46f9bb7df9cba0caf7b5cb/docs/Architecture.png)  
The Quagga container has `network_mode=host` so it sees the GRE tunnel, which is configured by Admin on the Linux Host.  
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

## How to setup
1. Choose a Linux host with Docker installed
2. Setup Topolograph:  
* launch your own Topolograph on docker using [topolograph-docker](https://github.com/Vadims06/topolograph-docker)
* or make sure you have a connection to the public https://topolograph.com  
** Remember `TOPOLOGRAPH_HOST`, `TOPOLOGRAPH_PORT` variables  
2.2. Create a user for API authentication using Local Registration form  
** Remember `TOPOLOGRAPH_USER_LOGIN`, `TOPOLOGRAPH_USER_PASS` variables  
2.3. Add your IP address in API/Authorised source IP ranges  
3. Setup ELK  
* if you already have ELK instance running, so just remember variables below
* if not - boot up a new ELK from [docker-elk](https://github.com/deviantony/docker-elk) compose
* Remember `ELASTIC_URL`, `ELASTIC_USER_LOGIN`, `ELASTIC_USER_PASS`  
4. Setup GRE tunnel from the host to a network device  
```bash
sudo modprobe ip_gre
sudo ip tunnel add tun0 mode gre remote <router-ip> local <host-ip> dev eth0 ttl 255
sudo ip address add <GRE tunnel ip address> dev tun0
sudo ip link set tun0 up
```
5. Setup GRE tunnel from the network device to the host. An example for Cisco
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
* Fill environment variables in docker-compose.yml file
* Start docker-compose  
```bash
docker-compose up -d
```

 ## Kibana settings
 Index Templates have already been created. It's needed to check that logs are received by ELK via `Kibana/Stack Management/Index Management`. `watcher-costs-changes` and `watcher-updown-events` should be in a list. Then create Index Pattern `Kibana/Stack Management/Index Pattern` -> `Create index pattern`, specify `watcher-costs-changes` as Index pattern name -> Next -> choose `watcher_time` as timestamp. Because the connection between Watcher (with Logstash) can be lost, but watcher continues to log all topology changes with the correct time. When the connection is repaired, all logs will be added to ELK and you can check the time of the incident. If you choose `@timestamp` - the time of all logs will be the time of their addition to ELK.  
