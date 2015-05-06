from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree
import pox.lib.packet as pkt

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr

from collections import namedtuple
import os
from collections import namedtuple
from csv import DictReader

import socket

log = core.getLogger()
Policy = namedtuple('Policy', ('src', 'dst'))
policyFile =  "%s/pox/firewall-policies.csv" % os.environ[ 'HOME' ]
portFile = "%s/pox/port-policies.csv" % os.environ[ 'HOME' ]

class VideoSlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

    def _handle_PacketIn (self, event):
        # Handle packet in messages from the switch to implement above algorithm.
        
        # print("new packet in")
        packet = event.parsed
        arp = event.parsed.find('arp')
        tcpp = event.parsed.find('tcp')
        icmp = event.parsed.find('icmp')

        def install_fwdrule(event,packet,outport):
            
            #install a flow table entry
            msg = of.ofp_flow_mod() 
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.priority=30
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port = outport))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def forward (message = None):
            this_dpid = dpid_to_str(event.dpid)

            if packet.dst.is_multicast:
                flood()
                return
            else:
                ippkt = packet.find('ipv4')
                log.debug("Got unicast packet for %s %s at %s (input port %d):",
                          ippkt.dstip, packet.dst, dpid_to_str(event.dpid), event.port)

                # slice the network
                if dpid_to_str(event.dpid) == '00-00-00-00-00-01' :
                    
                    destPort = tcpp.dstport
                    srcPort = tcpp.srcport
                    if destPort == 1880 or srcPort == 1880 :
                        log.debug("video service go high band")
                        if event.port == 3 or event.port == 4 or event.port == 5 or event.port == 6:
                            install_fwdrule(event,packet,2) 
                        else:
                            if ippkt.dstip == '10.0.0.1':
                                install_fwdrule(event,packet,3) 
                                log.debug("go to h1")
                            elif ippkt.dstip == '10.0.0.2':
                                install_fwdrule(event,packet,4) 
                                log.debug("go to h2")
                            elif ippkt.dstip == '10.0.0.3':
                                install_fwdrule(event,packet,5) 
                                log.debug("go to h3")
                            elif ippkt.dstip == '10.0.0.4':
                                install_fwdrule(event,packet,6) 
                                log.debug("go to h4")
                    else :
                        if event.port == 3 or event.port == 4 or event.port == 5 or event.port == 6:
                            install_fwdrule(event,packet,1) 
                            log.debug("no video service go low band")
                        else:
                            if ippkt.dstip == '10.0.0.1':
                                install_fwdrule(event,packet,3) 
                                log.debug("go to h1")
                            elif ippkt.dstip == '10.0.0.2':
                                install_fwdrule(event,packet,4) 
                                log.debug("go to h2")
                            elif ippkt.dstip == '10.0.0.3':
                                install_fwdrule(event,packet,5) 
                                log.debug("go to h3")
                            elif ippkt.dstip == '10.0.0.4':
                                install_fwdrule(event,packet,6) 
                                log.debug("go to h4")
                if dpid_to_str(event.dpid) == '00-00-00-00-00-02' :
                    if event.port == 1:
                        install_fwdrule(event,packet,2) 
                        log.debug("no video service go low band to s4")
                    else:
                        install_fwdrule(event,packet,1) 
                        log.debug("no video service go low band to s1")

                if dpid_to_str(event.dpid) == '00-00-00-00-00-03' :
                    if event.port == 1:
                        install_fwdrule(event,packet,2) 
                        log.debug(" video service go high band to s4")
                    else:
                        install_fwdrule(event,packet,1) 
                        log.debug("video service go high band to s1")
                    
                if dpid_to_str(event.dpid) == '00-00-00-00-00-04' :
                    log.debug("s4 destip %s", ippkt.dstip)
                    if ippkt.dstip == '10.0.0.5':
                        install_fwdrule(event,packet,3) 
                        log.debug("go to h5")
                    elif ippkt.dstip == '10.0.0.6':
                        install_fwdrule(event,packet,4) 
                        log.debug("go to h6")
                    elif tcpp.srcport == 1880:
                        install_fwdrule(event,packet,2) 
                        log.debug("go to s3")
                    else :
                        install_fwdrule(event,packet,1) 
                        log.debug("go to s2")


        # flood, but don't install the rule
        def flood (message = None):
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        if arp or icmp:
            flood()
            return
        forward()

    def _handle_ConnectionUp(self, event):
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        
        # implement firewall and port policies
        policies = self.read_policies(policyFile)
        ports = self.read_port_policies(portFile)

        for policy in policies.itervalues():
            if type(policy.src) is IPAddr and type(policy.dst) is IPAddr:
                log.debug("Source IP address is %s", policy.src)
                log.debug("Destination IP address is %s", policy.dst)

                match1 = of.ofp_match(dl_type=0x800,  nw_proto = pkt.ipv4.ICMP_PROTOCOL)
                match1.nw_src = policy.src
                match1.nw_dst = policy.dst

                # install the mods to block matching ip address for ICMP protocol
                fm1 = of.ofp_flow_mod()
                fm1.priority = 20  
                fm1.match = match1
                fm1.hard_timeout = 0
                event.connection.send(fm1)

                match2 = of.ofp_match(dl_type=0x800,  nw_proto = 6)
                match2.nw_src = policy.src
                match2.nw_dst = policy.dst

                # install the mods to block matching ip address for tcp protocol
                fm2 = of.ofp_flow_mod()
                fm2.priority = 20  
                fm2.match = match2
                fm2.hard_timeout = 0
                event.connection.send(fm2)

            elif type(policy.src) is EthAddr and type(policy.dst) is EthAddr:
                log.debug("Source Mac address is %s", policy.src)
                log.debug("Destination Mac address is %s", policy.dst)

                match = of.ofp_match(dl_src = policy.src, dl_dst = policy.dst)

                # install the mods to block matching mac address
                fm = of.ofp_flow_mod()
                fm.priority = 20  
                fm.match = match
                fm.hard_timeout = 0
                event.connection.send(fm)

            log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

        for port in ports.itervalues():
            log.debug("Forbidden Port number is %s", port)
            pmatch = of.ofp_match(dl_type=0x800,  nw_proto = 6, 
                                tp_dst = int(port))

            #installl the mods to block matching port number for tcp protocol
            pm = of.ofp_flow_mod()
            pm.priority = 20
            pm.match = pmatch
            pm.hard_timeout = 0
            event.connection.send(pm)

            log.debug("Port rules installed on %s", dpidToStr(event.dpid))
            

    def read_policies(self, file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")
            
            # read the firewall policies
            policies = {}
            for row in reader:
                addr1 = row['addr1']
                addr2 = row['addr2']
                if "." in addr1 and "." in addr2:
                    policies[row['id']] = Policy(IPAddr(addr1), IPAddr(addr2))
                else:
                    policies[row['id']] = Policy(EthAddr(addr1), EthAddr(addr2))
                
                print policies[row['id']]
        return policies

    def read_port_policies(self, file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")

            # read the port policies
            ports = {}
            for row in reader:
                ports[row['id']] = row['port']
        return ports

def launch():
    
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()
    
    # Starting the Video Slicing module
    core.registerNew(VideoSlice)
