# OSPF Topology Watcher
OSPF Topology Watcher is like a Git for developers - it helps to track OSPF topology changes and shows it on the history diagram. Changes are exported by Logstash to Elastic Stack (ELK).  
Logged topology changes:
* OSPF neighbor adjacency Up/Down
* OSPF link cost changes
* OSPF networks appeared/disappeared from the topology

## Architecture
![](https://github.com/Vadims06/ospfwatcher/blob/f218b754ac7b543ffe46f9bb7df9cba0caf7b5cb/docs/Architecture.png)
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
