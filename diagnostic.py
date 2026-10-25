from abc import abstractmethod
import re
from scapy.all import AsyncSniffer, IP, Raw, SndRcvList, PacketList, sniff
from scapy.config import conf
import netns
import time
import logging
import sys
from scapy.layers.l2 import GRE
from scapy.contrib.ospf import *

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
log = logging.getLogger(__name__)

import subprocess
import tempfile

class LinuxCommandNotFound(Exception):
    pass

class LINUX_HOST:

    @staticmethod
    def subprocess_output(command, if_raise=None):

        # Use tempfile, allowing a larger amount of memory. The subprocess.Popen
        # docs warn that the data read is buffered in memory. They suggest not to
        # use subprocess.PIPE if the data size is large or unlimited.
        try:
            with tempfile.TemporaryFile() as stdout_f, tempfile.TemporaryFile() as stderr_f:
                proc = subprocess.Popen(command, stdout=stdout_f, stderr=stderr_f)
                proc.wait()
                stderr_f.seek(0)
                err = stderr_f.read()
                stdout_f.seek(0)
                output = stdout_f.read()
        except:
            _msg = f"The {command} command is not available. Make sure it's installed."
            log.critical(_msg)
            if if_raise:
                raise LinuxCommandNotFound(_msg)
        return output, err, proc.returncode
    
    def get_conntrack(self, if_raise=None):
        """ Return a list of conntracks"""
        conntracks_ll = []
        out, err, returncode = self.subprocess_output(['conntrack', '-L'], if_raise=if_raise)
        if out is not None and isinstance(out, bytes):
            out = out.decode('utf-8')
        if returncode == 0:
            conntrack_re = re.compile(r'(?P<proto_name>\w+)\s+(?P<proto_num>\d+).*src=(?P<inner_src_ip>[\d.]+)\s+dst=(?P<inner_dst_ip>[\d.]+)\s.*src=(?P<outer_src_ip>[\d.]+)\s+dst=(?P<outer_dst_ip>[\d.]+)')
            conntrack_lines = out.splitlines()
            for line in conntrack_lines:
                conntrack_match = conntrack_re.match(line)
                if conntrack_match:
                    conntracks_ll.append(conntrack_match.groupdict())
        else:
            log.critical(f"Error executing conntrack: {err}")
        return conntracks_ll

class BASE:

    DUMP_FILTER_GRE = "proto gre"
    DUMP_FILTER_TIMEOUT = 10
    def __init__(self, if_names, nsname="") -> None:
        # variable to sniff packets
        self.if_names = if_names if isinstance(if_names, list) else [if_names]
        self.nsname = nsname
        self.packets: PacketList = []

    @property
    def sniffer(self):
        if hasattr(self, "_sniffer"):
            return self._sniffer
        if self.nsname:
            self.change_netns(self.nsname)
        self._sniffer = AsyncSniffer(iface=self.if_names, filter=self.DUMP_FILTER_GRE)
        return self._sniffer

    @staticmethod
    def change_netns(nsname) -> None:
        with netns.NetNS(nsname=nsname):
            conf.ifaces.reload()  # Reload interface list
            conf.route.resync()  # Reload IPv4 routes

    def do_print_progress_bar(self, timeout=10):
        import time
        import sys
        for i in range(1, timeout+1):
            sys.stdout.write('\r')
            # the exact output you're looking for:
            sys.stdout.write("[%-10s] %dsec" % ('='*i, i))
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write('\n\r')

    def run(self, nsname="") -> None:
        if nsname:
            self.change_netns(nsname)
        log.info(f"Start listening {self.if_names} interfaces")
        self.sniffer.start()
        # time.sleep(self.DUMP_FILTER_TIMEOUT)
        self.do_print_progress_bar(self.DUMP_FILTER_TIMEOUT)
        self.sniffer.stop()
        self.packets = self.sniffer.results

    @abstractmethod
    def is_watcher_alive(self):
        pass

    @abstractmethod
    def is_network_device_alive(self):
        pass

class WATCHER_NS(BASE):

    WATCHER_IP = "169.254.{watcher_num}.1"
    def __init__(self, if_names, nsname, watcher_internal_ip, network_device_ip) -> None:
        self.watcher_internal_ip = watcher_internal_ip
        self.network_device_ip = network_device_ip
        super().__init__(if_names, nsname)

    @property
    def is_watcher_alive(self):
        for pkt in self.packets:
            if pkt[IP].src == self.watcher_internal_ip:
                return True
        return False
    
    @property
    def is_network_device_alive(self):
        for pkt in self.packets:
            if pkt[IP].src == self.network_device_ip:
                return True
        return False


class WATCHER_HOST(BASE):
    """
    13:49:31.853767 IP 169.254.2.2 > 192.168.1.35: GREv0, length 72: IP 10.10.25.33 > 224.0.0.5: OSPFv2, Hello, length 48
    13:49:32.853323 IP 192.168.1.35 > 169.254.2.2: GREv0, length 72: IP 10.10.25.35 > 224.0.0.5: OSPFv2, Hello, length 48
    """
    def __init__(self, if_names, watcher_internal_ip, network_device_ip) -> None:
        self.watcher_internal_ip = watcher_internal_ip
        self.network_device_ip = network_device_ip
        super().__init__(if_names)

    @property
    def is_watcher_alive(self):
        for pkt in self.packets:
            try:
                if pkt[IP].src == self.watcher_internal_ip:
                    log.info("Watcher is alive")
                    return True
            except IndexError:
                # Layer IP not found
                pass
        log.critical(
            """FRR watcher doesn't send OSPF hellos over GRE. Please make sure that:
                1.FRR is running\n
                2.GRE1 is included into OSPF process `sudo docker exec -it <watcher-router> vtysh`
            """)
        return False

    @property
    def is_network_device_alive(self):
        for pkt in self.packets:
            try:
                if pkt[IP].src == self.network_device_ip:
                    log.info("Network device is alive")
                    return True
            except IndexError:
                # Layer IP not found
                pass
        log.critical(
            """Network device doesn't send OSPF hellos over GRE. Please make sure that:
                1.Network device has GRE interface configured \n
                2.Network device can reach Watcher's host
            """)
        return False

    def report(self):
        if not self.is_watcher_alive:
            log.critical(
                """FRR watcher doesn't send OSPF hellos over GRE. Please make sure that:
                    1.FRR is running\n
                    2.GRE1 is included into OSPF process `sudo docker exec -it <watcher-router> vtysh`
                """)
        if not self.is_network_device_alive:
            log.critical(
                """Network device doesn't send OSPF hellos over GRE. Please make sure that:
                    1.Network device has GRE interface configured \n
                    2.Network device can reach Watcher's host
                """)
        if self.is_watcher_alive and self.is_network_device_alive:
            log.info("Watcher and Network device have reachability")
    
    def ospf_mtu_match_check(self):
        ospf_mtu_match = OSPF_MTU_MATCH(self.if_names, self.watcher_internal_ip, self.network_device_ip)
        return ospf_mtu_match.check(self)
    
    def is_ospf_available(self):
        ospf_availability = OSPF_AVAILABILITY(self.watcher_internal_ip, self.network_device_ip)
        return ospf_availability.check(self)
    
    def does_conntrack_exist_for_gre(self):
        """ Check if connection for the network device exist. If new watcher has been created - no conntrack should exist for the same device
        gre      47 29 src=169.254.4.2 dst=192.168.1.35 srckey=0x0 dstkey=0x0 src=192.168.1.35 dst=192.168.1.33 srckey=0x0 dstkey=0x0 mark=0 use=1

        """
        conntracks_ll = LINUX_HOST().get_conntrack()
        for conntrack in conntracks_ll:
            if conntrack['proto_name'] != 'gre':
                continue
            if conntrack['inner_dst_ip'] == self.network_device_ip:
                log.critical(
                    f"""conntrack found {conntrack} for {self.network_device_ip}.
                    Remove it running:
                    sudo conntrack -D --src={conntrack['inner_src_ip']} or
                    sudo conntrack -D --dst={self.network_device_ip}"""
                )
                return True
        log.info(f"No conntrack connections found. Good to proceed.")


class IPTABLE_ENTRY_IP:
    def __init__(self, ip:str) -> None:
        import ipaddress
        try:
            self.ip = ipaddress.ip_interface(ip)
        except ValueError:
            self.ip = ""
    def __repr__(self):
        return str(self.ip)
    def __eq__(self, other):
        return str(self.ip) == other

class OSPF_BASE:

    OSPF_PROTO = 89

    def ospf_packets(self, dump_obj):
        for pkt in dump_obj.packets:
            try:
                if pkt[IP][GRE][IP].getfieldval('proto') != self.OSPF_PROTO:
                    continue
                yield pkt
            except IndexError as e:
                # Not a OSPF
                print(e)
                pass

class OSPF_AVAILABILITY(OSPF_BASE):

    def __init__(self, watcher_internal_ip, network_device_ip) -> None:
        self.watcher_internal_ip = watcher_internal_ip
        self.network_device_ip = network_device_ip

    def check(self, dump_obj):
        self.is_watcher_alive(dump_obj)
        self.is_network_device_alive(dump_obj)

    def is_watcher_alive(self, dump_obj):
        for pkt in self.ospf_packets(dump_obj=dump_obj):
            try:
                if pkt[IP].src == self.watcher_internal_ip:
                    log.info(f"Watcher {self.watcher_internal_ip} sends OSPF packets")
                    return True
            except Exception as e:
                print(e)
                pass
        else:
            log.critical(f"Network device {self.watcher_internal_ip} doesnt send OSPF packets")
        return False

    def is_network_device_alive(self, dump_obj):
        for pkt in self.ospf_packets(dump_obj=dump_obj):
            try:
                if pkt[IP].src == self.network_device_ip:
                    log.info(f"Network device {self.network_device_ip} sends OSPF packets")
                    return True
            except Exception as e:
                print(e)
                pass
        else:
            log.critical(f"Network device {self.network_device_ip} doesnt send OSPF packets")
        return False
        
class OSPF_MTU_MATCH(BASE, OSPF_BASE):
    
    DBDesc = 2
    OSPF_DBD_LAYER = 'OSPF Database Description'
    ASSERT_MSG = """MTU doesn't match. Change it on any side to make it equal. """
    
    def __init__(self, if_names, watcher_internal_ip, network_device_ip) -> None:
        self.watcher_internal_ip = watcher_internal_ip
        self.network_device_ip = network_device_ip
        # super().__init__(if_names)

    def check(self, dump_obj):
        a_end_mtu, b_end_mtu = 0, 0
        for pkt in self.ospf_packets(dump_obj=dump_obj):
            if a_end_mtu and b_end_mtu:
                break
            try:
                ospf_hdr = pkt[IP][GRE][IP].getlayer('OSPF Header')
                if ospf_hdr.getfieldval('type') != self.DBDesc:
                    continue
                mtu = ospf_hdr.getlayer(self.OSPF_DBD_LAYER).getfieldval('mtu')
                if pkt[IP].src == self.network_device_ip:
                    b_end_mtu = mtu
                elif pkt[IP].src == self.watcher_internal_ip:
                    a_end_mtu = mtu
            except IndexError as e:
                # Layer DBD not found
                print(e)
                pass
        else:
            if not a_end_mtu and not b_end_mtu:
                log.info(f"No DBD OSPF packets were detected. Check skipped.")
        if (a_end_mtu and b_end_mtu):
            if a_end_mtu == b_end_mtu:
                log.info(f"MTU match")
                return True
            else:
                log.critical(OSPF_MTU_MATCH.ASSERT_MSG + f"""{self.network_device_ip} has {b_end_mtu}, but {self.watcher_internal_ip} has {a_end_mtu}""")
                return False

class IPTABLES_NAT_FOR_REMOTE_NETWORK_DEVICE_UNIQUE:

    """
    Chain PREROUTING (policy ACCEPT 60 packets, 18006 bytes)
    num   pkts bytes target     prot opt in     out     source               destination
    2     1319  116K DNAT       47   --  *      *       192.168.1.35         192.168.1.33         to:169.254.2.2

    {'counters': (1311, 115368),
                 'dst': '192.168.1.33/32',
                 'protocol': 'gre',
                 'src': '192.168.1.35/32',
                 'target': {'DNAT': {'to-destination': '169.254.2.2'}}},
    """

    ASSERT_MSG = """
        Duplicated settings for the same device IP are found.
        It's possible to create GRE tunnel for a single Watcher - Network device pair only.
    """

    @staticmethod
    def check(network_device_ip):
        try:
            import iptc
        except Exception as e:
            log.info(f"Iptables checks are ignored, {e}")
            return True
        existed_nat_records_hash = set()
        for nat_table_row in iptc.easy.dump_chain('nat', 'PREROUTING', ipv6=False):
            if nat_table_row.get('src', '') != IPTABLE_ENTRY_IP(network_device_ip):
                continue
            dnat_ip = nat_table_row.get('target', {}).get('DNAT', {}).get('to-destination', '')
            existed_nat_records_hash.add((network_device_ip, dnat_ip))
        if not existed_nat_records_hash:
            log.critical(f"""There is no NAT settings for watcher, please check iptables, run:
            1. sudo iptables -nvL -t nat --line-numbers""")
            return False
        elif len(existed_nat_records_hash) == 1:
            log.info("NAT doesn't have settings for any other remote network device. Good to proceed.")
            return True
        log.critical(IPTABLES_NAT_FOR_REMOTE_NETWORK_DEVICE_UNIQUE.ASSERT_MSG +
            f"""Watcher's host has already {len(existed_nat_records_hash)} NAT records for {network_device_ip}.
            To remove them, run:
            1. sudo iptables -nvL -t nat --line-numbers
            2. sudo iptables -t nat -D PREROUTING <num>
            3. sudo conntrack -D --src={network_device_ip}"""
        )
        return False


class IPTABLES_REMOTE_NETWORK_DEVICE_NAT_TO_FRR_NETNS:
    """
    sudo iptables -nv -t nat -L PREROUTING --line-numbers | grep 192.168.1.35
    num   pkts bytes target     prot opt in     out     source               destination
    2     1311  115K DNAT       47   --  *      *       192.168.1.35         192.168.1.33         to:169.254.2.2
    3        0     0 DNAT       47   --  *      *       192.168.1.35         192.168.1.33         to:169.254.2.2
    """

    ASSERT_MSG = """
    Check if GRE packets sent by remote network device reaches Watcher host and redirected to FRR netns
    ! nat table counters are only incremented for the first packet of every connection. Then uses conntable
    If False, it means:
    * Network device doesn't sent packets:
        * GRE is not configured on network device or in Down state or Watcher's host is not available.
        Use ping <watcher's GRE IP> to check that GRE works.
        * GRE is not added into IGP process
        * If you have such option - dump outgoing packets from network device
        sudo tcpdump -i <int> proto gre and dst <watcher_ip> -n
    """
    @staticmethod
    def bash_cmd(network_device_ip):
        return f"sudo iptables -nv -t nat -L PREROUTING --line-numbers | grep {network_device_ip}"

    @staticmethod
    def check(network_device_ip):
        try:
            import iptc
        except Exception as e:
            print(f"Iptables checks are ignored, please use {IPTABLES_REMOTE_NETWORK_DEVICE_NAT_TO_FRR_NETNS.bash_cmd(network_device_ip)}")
            return True
        for nat_table_row in iptc.easy.dump_chain('nat', 'PREROUTING', ipv6=False):
            #for nat_table_row in nat_table['PREROUTING']:
            if nat_table_row.get('src', '') != IPTABLE_ENTRY_IP(network_device_ip):
                continue
            pkts, bytes = nat_table_row.get('counters', (0, 0))
            if pkts > 0:
                log.info("NAT is working for remote network device.")
                return True
            log.critical("NAT counter of packets from remote network device is Zero" + IPTABLES_REMOTE_NETWORK_DEVICE_NAT_TO_FRR_NETNS.ASSERT_MSG)
            return False


class IPTABLES_REMOTE_NETWORK_DEVICE_FORWARD_TO_FRR_NETNS:
    """
    sudo iptables -nv -t filter -L FORWARD --line-numbers | grep 192.168.1.35
    Chain FORWARD (policy DROP 0 packets, 0 bytes)
    num   pkts bytes target     prot opt in     out     source               destination
    12     928 85344 ACCEPT     47   --  *      *       192.168.1.35         0.0.0.0/0
    13    1074 97216 ACCEPT     47   --  vhost1025 *       169.254.2.2          192.168.1.35
    """
    ASSERT_MSG = """
        Check if GRE packets sent by watcher's FRR from FRR's netns reach host's namespace.
        If False, it means:
        * Network device doesn't sent packets:
         * GRE is not configured on network device or in Down state or Watcher's host is not available.
           Use ping <watcher's GRE IP> to check that GRE works.
         * GRE is not added into IGP process
         * If you have such option - dump outgoing packets from network device
           sudo tcpdump -i <int> proto gre and dst <watcher_ip> -n
        """
    @staticmethod
    def bash_cmd(network_device_ip):
        return f"sudo iptables -nv -t filter -L FORWARD --line-numbers | grep {network_device_ip}"

    @staticmethod
    def check(network_device_ip):
        try:
            import iptc
        except Exception as e:
            print(f"Iptables checks are ignored, please use {IPTABLES_REMOTE_NETWORK_DEVICE_FORWARD_TO_FRR_NETNS.bash_cmd(network_device_ip)}")
            return True
        for filter_table_row in iptc.easy.dump_chain('filter', 'FORWARD', ipv6=False):
            if filter_table_row.get('src', '') != IPTABLE_ENTRY_IP(network_device_ip):
                continue
            pkts, bytes = filter_table_row.get('counters', (0, 0))
            if pkts > 0:
                log.info("Remote network device sends IGP packets and iptables allows them.")
                return True
            log.critical("Remote network device doesn't send IGP packets" + IPTABLES_REMOTE_NETWORK_DEVICE_FORWARD_TO_FRR_NETNS.ASSERT_MSG)
            return False

class IPTABLES_FRR_NETNS_FORWARD_TO_NETWORK_DEVICE_BEFORE_NAT:

    ASSERT_MSG = """Check if GRE packets sent by watcher's FRR from FRR's netns reaches host's namespace.
    If False, it means:
    * IGP protocol is not enabled on Watcher's FRR
    * GRE1 is not enabled in FRR's netns. use `sudo ip netns exec watcher#-gre#-<protocol.-watcher ip l show dev gre1`
    """
    @staticmethod
    def bash_cmd(network_device_ip):
        return f"sudo iptables -nv -t filter -L FORWARD --line-numbers | grep {network_device_ip}"

    @staticmethod
    def check(network_device_ip):
        try:
            import iptc
        except Exception as e:
            print(f"Iptables checks are ignored, please use {IPTABLES_FRR_NETNS_FORWARD_TO_NETWORK_DEVICE_BEFORE_NAT.bash_cmd(network_device_ip)}")
            return True
        for filter_table_row in iptc.easy.dump_chain('filter', 'FORWARD', ipv6=False):
            if filter_table_row.get('dst', '') != IPTABLE_ENTRY_IP(network_device_ip):
                continue
            pkts, bytes = filter_table_row.get('counters', (0, 0))
            if pkts > 0:
                log.info("Watcher's FRR sends IGP packets and iptables allows them.")
                return True
            log.critical("Watcher's FRR doesn't send IGP packets" + IPTABLES_FRR_NETNS_FORWARD_TO_NETWORK_DEVICE_BEFORE_NAT.ASSERT_MSG)
            return False
