import argparse
import copy
import enum
import ipaddress
import os
import re
import shutil
import sys
from io import StringIO

import requests
from jinja2 import Environment, FileSystemLoader
from ruamel.yaml import YAML

import diagnostic

ruamel_yaml_default_mode = YAML()
ruamel_yaml_default_mode.width = 2048  # type: ignore

class ACTIONS(enum.Enum):
    ADD_WATCHER = "add_watcher"
    DIAGNOSTIC = "diagnostic"
    ENABLE_XDP = "enable_xdp"
    DISABLE_XDP = "disable_xdp"


class WATCHER_CONFIG:
    P2P_VETH_SUPERNET_W_MASK = "169.254.0.0/16"
    WATCHER_ROOT_FOLDER = "watcher"
    WATCHER_TEMPLATE_FOLDER_NAME = "watcher-template"
    WATCHER_CONFIG_FILE = "config.yml"
    ROUTER_NODE_NAME = "router"
    WATCHER_NODE_NAME = "ospf-watcher"
    OSPF_FILTER_NODE_NAME = "receive_only_filter"
    OSPF_FILTER_NODE_IMAGE = "vadims06/ospf-filter-xdp:latest"
    LOGROTATION_NODE_NAME = "logrotation"
    LOGROTATION_IMAGE = "vadims06/docker-logrotate:v1.0.0"

    def __init__(self, watcher_num, protocol="ospf"):
        self.watcher_num = watcher_num
        # default
        self.gre_tunnel_network_device_ip = ""
        self.gre_tunnel_ip_w_mask_network_device = ""
        self.gre_tunnel_ip_w_mask_watcher = ""
        self.gre_tunnel_number = 0
        self.ospf_area_num = "" # 0.0.0.0
        self.host_interface_device_ip = ""
        self.protocol = protocol
        self.asn = 0
        self.organisation_name = ""
        self.watcher_name = ""

    @staticmethod
    def gen_next_free_number():
        """ Each Watcher installation has own sequence number starting from 1 """
        watcher_seq_numbers = [int(folder_name.split('-')[0][7:]) for folder_name in WATCHER_CONFIG.get_existed_watchers() if '-' in folder_name]
        if not watcher_seq_numbers:
            return 1
        expected_numbers = set(range(1, max(watcher_seq_numbers) + 1))
        if set(expected_numbers) == set(watcher_seq_numbers):
            next_number = len(watcher_seq_numbers) + 1
        else:
            next_number = next(iter(expected_numbers - set(watcher_seq_numbers)))
        return next_number

    @staticmethod
    def get_existed_watchers():
        """ Return a list of watcher folders """
        watcher_root_folder_path = os.path.join(os.getcwd(), WATCHER_CONFIG.WATCHER_ROOT_FOLDER)
        return [file for file in os.listdir(watcher_root_folder_path) if os.path.isdir(os.path.join(watcher_root_folder_path, file)) and file.startswith("watcher") and not file.endswith("template")]

    def gen_watcher_number(self):
        numbers = [folder_name.split('-')[0] for folder_name in self.get_existed_watchers() if '-' in folder_name]
        expected_numbers = set(range(1, max(numbers) + 1))
        missing_number = next(iter(expected_numbers - set(numbers)))
        return missing_number

    def import_from(self, watcher_num):
        """
        Browse a folder directory and find a folder with watcher num. Parse GRE tunnel
        """
        # watcher1-gre1025-ospf
        watcher_re = re.compile("(?P<name>[a-zA-Z]+)(?P<watcher_num>\d+)-gre(?P<gre_num>\d+)(-(?P<proto>[a-zA-Z]+))?")
        for file in self.get_existed_watchers():
            watcher_match = watcher_re.match(file)
            if watcher_match and watcher_match.groupdict().get("watcher_num", "") == str(watcher_num):
                # these two attributes are needed to build paths
                self.protocol = watcher_match.groupdict().get("proto") if watcher_match.groupdict().get("proto") else self.protocol
                self.gre_tunnel_number = int(watcher_match.groupdict().get("gre_num", 0))
                for label, value in self.watcher_config_file_yml.get('topology', {}).get('defaults', {}).get('labels', {}).items():
                    setattr(self, label, value)
                break
        else:
            raise ValueError(f"Watcher{watcher_num} was not found")

    def diagnostic_watcher_host(self):
        return diagnostic.WATCHER_HOST(
            if_names=[self.host_veth],
            watcher_internal_ip=self.p2p_veth_watcher_ip,
            network_device_ip=self.gre_tunnel_network_device_ip
        )

    @property
    def p2p_veth_network_obj(self):
        p2p_super_network_obj = ipaddress.ip_network(self.P2P_VETH_SUPERNET_W_MASK)
        return self.get_nth_elem_from_iter(p2p_super_network_obj.subnets(new_prefix=24), self.watcher_num + 1)

    @property
    def p2p_veth_watcher_ip_obj(self):
        return self.get_nth_elem_from_iter(self.p2p_veth_network_obj.hosts(), 2)

    @property
    def p2p_veth_watcher_ip_w_mask(self):
        return f"{str(self.p2p_veth_watcher_ip_obj)}/{self.p2p_veth_network_obj.prefixlen}"

    @property
    def p2p_veth_watcher_ip_w_slash_32_mask(self):
        return f"{str(self.p2p_veth_watcher_ip_obj)}/32"

    @property
    def p2p_veth_watcher_ip(self):
        return str(self.p2p_veth_watcher_ip_obj)

    @property
    def p2p_veth_host_ip_obj(self):
        return self.get_nth_elem_from_iter(self.p2p_veth_network_obj.hosts(), 1)

    @property
    def p2p_veth_host_ip_w_mask(self):
        return f"{str(self.p2p_veth_host_ip_obj)}/{self.p2p_veth_network_obj.prefixlen}"

    @property
    def host_veth(self):
        """ Add organisation name at name of interface to allow different interfaces with the same GRE num """
        linux_ip_link_peer_max_len = 15
        vhost_inf_name = f"vhost{self.gre_tunnel_number}"
        organisation_name_short = self.organisation_name[:linux_ip_link_peer_max_len - (len(vhost_inf_name)+1)] # 1 for dash
        self._host_veth = f"{organisation_name_short}-{vhost_inf_name}" if organisation_name_short else vhost_inf_name
        return self._host_veth

    @host_veth.setter
    def host_veth(self, value_from_yaml_import):
        self._host_veth = value_from_yaml_import

    @property
    def watcher_root_folder_path(self):
        return os.path.join(os.getcwd(), self.WATCHER_ROOT_FOLDER)

    @property
    def watcher_folder_name(self):
        return f"watcher{self.watcher_num}-gre{self.gre_tunnel_number}-{self.protocol}"

    @property
    def watcher_log_file_name(self):
        return f"{self.watcher_folder_name}.{self.protocol}.log"

    @property
    def watcher_folder_path(self):
        return os.path.join(self.watcher_root_folder_path, self.watcher_folder_name)

    @property
    def watcher_template_path(self):
        return os.path.join(self.watcher_root_folder_path, self.WATCHER_TEMPLATE_FOLDER_NAME)

    @property
    def router_template_path(self):
        return os.path.join(self.watcher_template_path, self.ROUTER_NODE_NAME)

    @property
    def router_folder_path(self):
        return os.path.join(self.watcher_folder_path, self.ROUTER_NODE_NAME)
    
    @property
    def watcher_config_file_path(self):
        return os.path.join(self.watcher_folder_path, self.WATCHER_CONFIG_FILE)

    @property
    def watcher_config_file_yml(self) -> dict:
        if os.path.exists(self.watcher_config_file_path):
            with open(self.watcher_config_file_path) as f:
                return ruamel_yaml_default_mode.load(f)
        return {}

    @property
    def watcher_config_template_yml(self):
        watcher_template_path = os.path.join(self.watcher_root_folder_path, self.WATCHER_TEMPLATE_FOLDER_NAME)
        with open(os.path.join(watcher_template_path, self.WATCHER_CONFIG_FILE)) as f:
            return ruamel_yaml_default_mode.load(f)

    @property
    def ospf_watcher_template_path(self):
        return os.path.join(self.watcher_template_path, self.WATCHER_NODE_NAME)

    @property
    def ospf_watcher_folder_path(self):
        return os.path.join(self.watcher_folder_path, self.WATCHER_NODE_NAME)
        
    @property
    def netns_name(self):
        watcher_config_yml = self.watcher_config_template_yml
        if not watcher_config_yml.get("prefix"):
            return f"clab-{self.watcher_folder_name}-{self.ROUTER_NODE_NAME}"
        elif watcher_config_yml["prefix"] == "__lab-name":
            return f"{self.watcher_folder_name}-{self.ROUTER_NODE_NAME}"
        elif watcher_config_yml["prefix"] != "":
            return f"{watcher_config_yml['prefix']}-{self.watcher_folder_name}-{self.ROUTER_NODE_NAME}"
        return self.ROUTER_NODE_NAME

    @staticmethod
    def do_check_ip(ip_address_w_mask):
        try:
            return str(ipaddress.ip_interface(ip_address_w_mask).ip)
        except:
            return ""

    @staticmethod
    def do_check_area_num(area_num):
        """ area only digits. max 32 it shouldn't be more. 0-4'294'967'295 FRR """
        area_match = re.match('^\d{1,32}$', area_num)
        area_in_ip_notation = ""
        if area_match:
            area_in_ip_notation = str(ipaddress.ip_address(int(area_match.group(0)))) if int(area_match.group(0)) != 0 else "0.0.0.0"
        elif re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', area_num):
            area_in_ip_notation = area_num
        return area_in_ip_notation


    def _add_topolograph_host_to_env(self):
        # open local .env file and replace TOPOLOGRAPH_HOST env
        with open('.env', 'r') as f:
            lines = f.readlines()
        with open('.env', 'w') as f:
            for line in lines:
                if line.startswith('TOPOLOGRAPH_HOST'):
                    f.write(f'TOPOLOGRAPH_HOST={self.host_interface_device_ip}\n')
                    print(f"TOPOLOGRAPH_HOST set to {self.host_interface_device_ip} in .env\n")
                elif line.startswith('WEBHOOK_URL'):
                    f.write(f'WEBHOOK_URL={self.host_interface_device_ip}\n')
                    print(f"WEBHOOK_URL set to {self.host_interface_device_ip} in .env\n")
                else:
                    f.write(line)

    def do_check_topolograph_availability(self):
        from dotenv import load_dotenv
        load_dotenv()
        # using TOPOLOGRAPH_* env variable check if get request is ok
        _login, _pass = os.getenv('TOPOLOGRAPH_WEB_API_USERNAME_EMAIL', ''), os.getenv('TOPOLOGRAPH_WEB_API_PASSWORD', '')
        _host, _port = os.getenv('TOPOLOGRAPH_HOST', ''), os.getenv('TOPOLOGRAPH_PORT', '')
        try:
            r_get = requests.get(f'http://{_host}:{_port}/api/graph/', auth=(_login, _pass), timeout=(5, 30))
        except requests.exceptions.ConnectionError:
            raise(f"couldn't connect to {_host}:{_port}. Please check that Topolograph is accessible and {_login} user is created")
        status_name = 'ok' if r_get.ok else 'bad'
        print(f"Access to {_host}:{_port} is {status_name}")
        if r_get.status_code != 200:
            print(f"Access to {_host}:{_port} is {r_get.status_code} error, details: {r_get.text}")
        return r_get.ok

    @staticmethod
    def _get_digit_net_mask(ip_address_w_mask):
        return ipaddress.ip_interface(ip_address_w_mask).network.prefixlen

    @property
    def tunnel_subnet_w_digit_mask(self):
        if self.do_check_ip(self.gre_tunnel_ip_w_mask_network_device):
            return str(ipaddress.ip_interface(self.gre_tunnel_ip_w_mask_network_device).network)
        return ""

    @staticmethod
    def get_nth_elem_from_iter(iterator, number):
        while number > 0:
            value = iterator.__next__()
            number -= 1
        return value

    @staticmethod
    def is_network_the_same(ip_address_w_mask_1, ip_address_w_mask_2):
        return ipaddress.ip_interface(ip_address_w_mask_1).network == ipaddress.ip_interface(ip_address_w_mask_2).network

    def create_folder_with_settings(self):
        # watcher folder
        os.mkdir(self.watcher_folder_path)
        # ospf-watcher folder
        watcher_logs_folder_path = os.path.join(self.watcher_root_folder_path, "logs")
        if not os.path.exists(watcher_logs_folder_path):
            os.mkdir(watcher_logs_folder_path)
        # create file
        with open(os.path.join(watcher_logs_folder_path, self.watcher_log_file_name), 'w') as fp:
            pass
        os.chmod(os.path.join(watcher_logs_folder_path, self.watcher_log_file_name), 0o755)
        # router folder inside watcher
        os.mkdir(self.router_folder_path)
        for file_name in ["daemons"]:
            shutil.copyfile(
                src=os.path.join(self.router_template_path, file_name),
                dst=os.path.join(self.router_folder_path, file_name)
            )
        # Config generation
        env = Environment(
            loader=FileSystemLoader(self.router_template_path)
        )
        # frr.conf
        frr_template = env.get_template("frr.template")
        frr_config = frr_template.render(
            tunnel_subnet_w_digit_mask=str(self.tunnel_subnet_w_digit_mask),
            area_num=str(self.ospf_area_num),
            watcher_name=self.watcher_folder_name,
        )
        with open(os.path.join(self.router_folder_path, "frr.conf"), "w") as f:
            f.write(frr_config)
        # vtysh.conf
        vtysh_template = env.get_template("vtysh.template")
        vtysh_config = vtysh_template.render(watcher_name=self.watcher_folder_name)
        with open(os.path.join(self.router_folder_path, "vtysh.conf"), "w") as f:
            f.write(vtysh_config)
        # containerlab config
        watcher_config_yml = self.watcher_config_template_yml
        watcher_config_yml["name"] = self.watcher_folder_name
        # remember user input for further user, i.e diagnostic
        watcher_config_yml['topology']['defaults']['labels'].update({'gre_tunnel_number': int(self.gre_tunnel_number)})
        watcher_config_yml['topology']['defaults']['labels'].update({'gre_tunnel_network_device_ip': self.gre_tunnel_network_device_ip})
        watcher_config_yml['topology']['defaults']['labels'].update({'gre_tunnel_ip_w_mask_network_device': self.gre_tunnel_ip_w_mask_network_device})
        watcher_config_yml['topology']['defaults']['labels'].update({'gre_tunnel_ip_w_mask_watcher': self.gre_tunnel_ip_w_mask_watcher})
        watcher_config_yml['topology']['defaults']['labels'].update({'ospf_area_num': self.ospf_area_num})
        watcher_config_yml['topology']['defaults']['labels'].update({'asn': self.asn})
        watcher_config_yml['topology']['defaults']['labels'].update({'organisation_name': self.organisation_name})
        watcher_config_yml['topology']['defaults']['labels'].update({'watcher_name': self.watcher_name})
        watcher_config_yml['topology']['defaults']['labels'].update({'host_veth': self.host_veth})
        # Config
        watcher_config_yml['topology']['nodes']['h1']['exec'] = self.exec_cmds()
        watcher_config_yml['topology']['links'] = [{'endpoints': [f'{self.ROUTER_NODE_NAME}:veth1', f'host:{self.host_veth}']}]
        # Watcher
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['network-mode'] = f"container:{self.ROUTER_NODE_NAME}"
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['binds'].append(f"../logs/{self.watcher_log_file_name}:/home/watcher/watcher/logs/watcher.log")
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME].update({'env': {'ASN': self.asn}})
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['env'].update({'WATCHER_NAME': self.watcher_name})
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['env'].update({'AREA_NUM': self.ospf_area_num})
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['env'].update({'WATCHER_INTERFACE': "veth1"})
        watcher_config_yml['topology']['nodes'][self.WATCHER_NODE_NAME]['env'].update({'WATCHER_LOGFILE': "/home/watcher/watcher/logs/watcher.log"})
        # Logrotation
        watcher_config_yml['topology']['nodes'][self.LOGROTATION_NODE_NAME]['image'] = self.LOGROTATION_IMAGE
        watcher_config_yml['topology']['nodes'][self.LOGROTATION_NODE_NAME].setdefault('binds', []).append(f"../logs/{self.watcher_log_file_name}:/logs/watcher.log")
        # OSPF XDP filter, listen only. Not ready right now
        if self.enable_xdp:
            watcher_config_yml['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['image'] = self.OSPF_FILTER_NODE_IMAGE
            watcher_config_yml['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['network-mode'] = "host"
            watcher_config_yml['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['env']['VTAP_HOST_INTERFACE'] = self.host_veth
        else:
            del watcher_config_yml['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]
            for d in watcher_config_yml['topology']['nodes']['h2']['stages']['create']['wait-for']:
                if d.get("node") == self.OSPF_FILTER_NODE_NAME:
                    d['node'] = 'h1'
        # Enable GRE after XDP filter
        watcher_config_yml['topology']['nodes']['h2']['exec'] = [f'sudo ip netns exec {self.netns_name} ip link set up dev gre1']
        self._do_save_watcher_config_file(watcher_config_yml)

    def _do_save_watcher_config_file(self, _config):
        with open(self.watcher_config_file_path, "w") as f:
            s = StringIO()
            ruamel_yaml_default_mode.dump(_config, s)
            f.write(s.getvalue())

    def do_watcher_postchecks(self):
        if os.path.exists(self.watcher_folder_path):
            raise ValueError(f"Watcher{self.watcher_num} with GRE{self.gre_tunnel_number} already exists")
        # TODO, check if GRE with the same tunnel destination already exist without root access
        # Requires root access. TODO https://stackoverflow.com/questions/72015197/allow-non-root-user-of-container-to-execute-binaries-that-need-capabilities
        # diag_watcher_host = self.diagnostic_watcher_host()
        # diagnostic.IPTABLES_NAT_FOR_REMOTE_NETWORK_DEVICE_UNIQUE.check(self.gre_tunnel_network_device_ip)
        # diag_watcher_host.does_conntrack_exist_for_gre()

    @staticmethod
    def do_print_banner():
        print("""
+---------------------------+                                        
|  Watcher Host             |                       +-------------------+                                       
|  +------------+           |                       | Network device    |       
|  | netns FRR  |           |                       |                   |
|  |            Tunnel [4]  |                       | Tunnel [4]        |
|  |  gre1   [3]TunnelIP----+-----------------------+[2]TunnelIP        |
|  |  eth1------+-vhost1    |       +-----+         | OSPF area num [5] |
|  |            | Host IP[6]+-------+ LAN |--------[1]Device IP         |
|  |            |           |       +-----+         |                   |
|  +------------+           |                       |                   |
|                           |                       +-------------------+
+---------------------------+                                        
        """)

    def add_watcher_dialog(self):
        while not self.gre_tunnel_network_device_ip:
            self.gre_tunnel_network_device_ip = self.do_check_ip(input("[1]Network device IP [x.x.x.x]: "))
        while not self.gre_tunnel_ip_w_mask_network_device:
            self.gre_tunnel_ip_w_mask_network_device = input("[2]GRE Tunnel IP on network device with mask [x.x.x.x/yy]: ")
            if not self.do_check_ip(self.gre_tunnel_ip_w_mask_network_device):
                print("IP address is not correct")
                self.gre_tunnel_ip_w_mask_network_device = ""
            elif self._get_digit_net_mask(self.gre_tunnel_ip_w_mask_network_device) == 32:
                print("Please provide non /32 subnet for tunnel network")
                self.gre_tunnel_ip_w_mask_network_device = ""
            elif self.gre_tunnel_ip_w_mask_network_device == self.gre_tunnel_network_device_ip:
                print("Tunnel IP address shouldn't be the same as physical device IP address")
                self.gre_tunnel_ip_w_mask_network_device = ""
        while not self.gre_tunnel_ip_w_mask_watcher:
            self.gre_tunnel_ip_w_mask_watcher = input("[3]GRE Tunnel IP on Watcher with mask [x.x.x.x/yy]: ")
            if not self.do_check_ip(self.gre_tunnel_ip_w_mask_watcher):
                print("IP address is not correct")
                self.gre_tunnel_ip_w_mask_watcher = ""
            elif self._get_digit_net_mask(self.gre_tunnel_ip_w_mask_watcher) == 32:
                print("Please provide non /32 subnet for tunnel network")
                self.gre_tunnel_ip_w_mask_watcher = ""
            elif not self.is_network_the_same(self.gre_tunnel_ip_w_mask_network_device, self.gre_tunnel_ip_w_mask_watcher):
                print("Tunnel's network doesn't match")
                self.gre_tunnel_ip_w_mask_watcher = ""
            elif self.gre_tunnel_ip_w_mask_network_device == self.gre_tunnel_ip_w_mask_watcher:
                print("Tunnel' IP addresses must be different on endpoints")
                self.gre_tunnel_ip_w_mask_watcher = ""
        while not self.gre_tunnel_number:
            self.gre_tunnel_number = input("[4]GRE Tunnel number: ")
            if not self.gre_tunnel_number.isdigit():
                print("Please provide any positive number")
                self.gre_tunnel_number = ""
            else:
                self.gre_tunnel_number = int(self.gre_tunnel_number)
        # OSPF settings
        while not self.ospf_area_num:
            self.ospf_area_num = self.do_check_area_num(input("[5]OSPF area number [\d+|\d+.\d+.\d+.\d+], i.e 0 or 63.0.0.0: "))
        # Host interface name for NAT
        while not self.host_interface_device_ip:
            self.host_interface_device_ip = self.do_check_ip(input("[6]Watcher host IP address: "))
        # Topolograph's IP settings
        self.enable_topolograph = None
        while self.enable_topolograph is None:
            enable_topolograph_reply = input("Enable Topolograph? [Y/n] ")
            if not enable_topolograph_reply:
                self.enable_topolograph = True
            else:
                if enable_topolograph_reply.lower().strip() == 'y':
                    self.enable_topolograph = True
                elif enable_topolograph_reply.lower().strip() == 'n':
                    self.enable_topolograph = False
        if self.enable_topolograph:
            self._add_topolograph_host_to_env()
            self.do_check_topolograph_availability()
        # Tags
        self.asn = input("AS number, where OSPF is configured: [0]")
        if not self.asn and not self.asn.isdigit():
            self.asn = 0
        self.organisation_name = str(input("Organisation name: ")).lower()
        self.watcher_name = str(input("Watcher name: ")).lower().replace(" ", "-")
        if not self.watcher_name:
            self.watcher_name = "ospfwatcher-demo"
        self.enable_xdp = None
        while self.enable_xdp is None:
            enable_xdp_reply = input("Enable XDP? [y/N] ")
            if not enable_xdp_reply:
                self.enable_xdp = False
            else:
                if enable_xdp_reply.lower().strip() == 'y':
                    self.enable_xdp = True
                elif enable_xdp_reply.lower().strip() == 'n':
                    self.enable_xdp = False
    
    def exec_cmds(self):
        return [
            f'ip netns exec {self.netns_name} ip address add {self.p2p_veth_watcher_ip_w_mask} dev veth1',
            f'ip netns exec {self.netns_name} ip route add {self.gre_tunnel_network_device_ip} via {str(self.p2p_veth_host_ip_obj)}',
            f'ip address add {self.p2p_veth_host_ip_w_mask} dev {self.host_veth}',
            f'ip netns exec {self.netns_name} ip tunnel add gre1 mode gre local {str(self.p2p_veth_watcher_ip_obj)} remote {self.gre_tunnel_network_device_ip} ttl 100',
            f'ip netns exec {self.netns_name} ip address add {self.gre_tunnel_ip_w_mask_watcher} dev gre1',
            f'bash -c \'RULE="-t nat -p gre -s {self.p2p_veth_watcher_ip} -d {self.gre_tunnel_network_device_ip} -j SNAT --to-source {self.host_interface_device_ip}"; sudo iptables -C POSTROUTING $$RULE &> /dev/null && echo "Rule exists in iptables." || sudo iptables -A POSTROUTING $$RULE\'',
            f'bash -c \'RULE="-t nat -p gre -s {self.gre_tunnel_network_device_ip} -d {self.host_interface_device_ip} -j DNAT --to-destination {self.p2p_veth_watcher_ip}"; sudo iptables -C PREROUTING $$RULE &> /dev/null && echo "Rule exists in iptables." || sudo iptables -A PREROUTING $$RULE\'',
            f'bash -c \'RULE="-t filter -p gre -s {self.p2p_veth_watcher_ip} -d {self.gre_tunnel_network_device_ip} -i {self.host_veth} -j ACCEPT"; sudo iptables -C FORWARD $$RULE &> /dev/null && echo "Rule exists in iptables." || sudo iptables -A FORWARD $$RULE\'',
            f'bash -c \'RULE="-t filter -p gre -s {self.gre_tunnel_network_device_ip} -j ACCEPT"; sudo iptables -C FORWARD $$RULE &> /dev/null && echo "Rule exists in iptables." || sudo iptables -A FORWARD $$RULE\'',
            f'sudo ip netns exec {self.netns_name} ip link set mtu 1476 dev gre1', # 1476 - 24 GRE encap for OSPF MTU match
            f'sudo ip netns exec {self.netns_name} ip link set mtu 1500 dev veth1', # for xdp
            # enable GRE after applying XDP filter
            # f'sudo ip netns exec {self.netns_name} ip link set up dev gre1',
            f'sudo ip link set mtu 1500 dev {self.host_veth}',
            f'sudo conntrack -D --dst {self.gre_tunnel_network_device_ip} -p 47',
            f'sudo conntrack -D --src {self.gre_tunnel_network_device_ip} -p 47',
        ]

    @classmethod
    def parse_command_args(cls, args):
        allowed_actions = [actions.value for actions in ACTIONS]
        if args.action not in allowed_actions:
            raise ValueError(f"Not allowed action. Supported actions: {', '.join(allowed_actions)}")
        watcher_num = args.watcher_num if args.watcher_num else cls.gen_next_free_number()
        watcher_obj = cls(watcher_num)
        watcher_obj.run_command(args.action)

    def run_command(self, action):
        method = getattr(self, action)
        return method()

    def add_watcher(self):
        self.do_print_banner()
        # pre-check mandatory Linux tools installed
        # diagnostic.LINUX_HOST().get_conntrack(if_raise=True) # Operation failed: sorry, you must be root or get CAP_NET_ADMIN capability to do this
        self.add_watcher_dialog()
        self.do_watcher_postchecks()
        # create folder
        self.create_folder_with_settings()
        print(f"Config has been successfully generated!")

    def stop_watcher(self):
        raise NotImplementedError("Not implemented yet. Please run manually `sudo clab destroy --topo <path to config.yml>`")

    def get_status(self):
        # TODO add OSPF neighborship status
        raise NotImplementedError("Not implemented yet. Please run manually `sudo docker ps -f label=clab-node-name=router`")

    def diagnostic(self):
        print(f"Diagnostic connection is started")
        self.import_from(watcher_num=args.watcher_num)
        diag_watcher_host = diagnostic.WATCHER_HOST(
            if_names=[self.host_veth],
            watcher_internal_ip=self.p2p_veth_watcher_ip,
            network_device_ip=self.gre_tunnel_network_device_ip
        )
        diag_watcher_host.does_conntrack_exist_for_gre()
        # print(f"Please wait {diag_watcher_host.DUMP_FILTER_TIMEOUT} sec")
        diag_watcher_host.run()
        if not diagnostic.IPTABLES_NAT_FOR_REMOTE_NETWORK_DEVICE_UNIQUE.check(self.gre_tunnel_network_device_ip):
            sys.exit()
        if diag_watcher_host.is_watcher_alive:
            diagnostic.IPTABLES_FRR_NETNS_FORWARD_TO_NETWORK_DEVICE_BEFORE_NAT.check(self.gre_tunnel_network_device_ip)
        if diag_watcher_host.is_network_device_alive:
            is_passed = diagnostic.IPTABLES_REMOTE_NETWORK_DEVICE_FORWARD_TO_FRR_NETNS.check(self.gre_tunnel_network_device_ip)
            if not is_passed:
                diagnostic.IPTABLES_REMOTE_NETWORK_DEVICE_NAT_TO_FRR_NETNS.check(self.gre_tunnel_network_device_ip)
        # OSPF
        diag_watcher_host.is_ospf_available()
        diag_watcher_host.ospf_mtu_match_check()

    def enable_xdp(self):
        self.import_from(watcher_num=args.watcher_num)
        current_clab_config = self.watcher_config_file_yml
        if not current_clab_config:
            raise ValueError(f"config file for watcher #{args.watcher_num} was not found")
        current_clab_config['topology']['nodes'].setdefault(self.OSPF_FILTER_NODE_NAME, dict()).update( copy.deepcopy(self.watcher_config_template_yml['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]) )
        current_clab_config['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['image'] = self.OSPF_FILTER_NODE_IMAGE
        current_clab_config['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['network-mode'] = "host"
        current_clab_config['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]['env']['VTAP_HOST_INTERFACE'] = self.host_veth

        current_clab_config['topology']['nodes']['h2'].setdefault('stages', dict()).update( copy.deepcopy(self.watcher_config_template_yml['topology']['nodes']['h2']['stages']) )
        self._do_save_watcher_config_file(current_clab_config)
        print("XDP enabled")

    def disable_xdp(self):
        self.import_from(watcher_num=args.watcher_num)
        current_clab_config = self.watcher_config_file_yml
        if not current_clab_config:
            raise ValueError(f"config file for watcher #{args.watcher_num} was not found")
        del current_clab_config['topology']['nodes'][self.OSPF_FILTER_NODE_NAME]
        for d in current_clab_config['topology']['nodes']['h2']['stages']['create']['wait-for']:
            if d.get("node") == self.OSPF_FILTER_NODE_NAME:
                d['node'] = 'h1'
        self._do_save_watcher_config_file(current_clab_config)
        print("XDP disabled")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Provisioning Watcher instances for tracking OSPF topology changes"
    )
    parser.add_argument(
        "--action", required=True, help="Options: add_watcher, enable_xdp, disable_xdp, diagnostic"
    )
    parser.add_argument(
        "--watcher_num", required=False, default=0, type=int, help="Number of watcher"
    )
    
    args = parser.parse_args()
    allowed_actions = [actions.value for actions in ACTIONS]
    if args.action not in allowed_actions:
        raise ValueError(f"Not allowed action. Supported actions: {', '.join(allowed_actions)}")
    try:
        watcher_conf = WATCHER_CONFIG.parse_command_args(args)
    except KeyboardInterrupt:
        print("\nInterrupted. Bye!")
        sys.exit(1)