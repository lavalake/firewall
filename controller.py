'''
Please add your name:
Please add your matric number: 
'''

from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class VideoSlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        print("new packet in")
        packet = event.parsed
        arp = event.parsed.find('arp')
        tcpp = event.parsed.find('tcp')
        icmp = event.parsed.find('icmp')

        def install_fwdrule(event,packet,outport):
            msg = of.ofp_flow_mod() #install a flow table entry
            msg.idle_timeout = 10
            msg.hard_timeout = 30
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
                log.debug("Got unicast packet for %s at %s (input port %d):",
                          packet.dst, dpid_to_str(event.dpid), event.port)
                '''

                Add your logic here to slice the network

                '''
                ippkt = packet.find('ipv4')
                if dpid_to_str(event.dpid) == '00-00-00-00-00-01' :
                    
                    destPort = tcpp.dstport
                    srcPort = tcpp.srcport
                    if destPort == 1880 or srcPort == 1880 :
                        log.debug("video service go high band")
                        if event.port == 3 or event.port == 4:
                            install_fwdrule(event,packet,2) 
                        else:
                            if ippkt.dstip == '10.0.0.1':
                                install_fwdrule(event,packet,3) 
                                log.debug("go to h1")
                            else:
                                install_fwdrule(event,packet,4) 
                                log.debug("go to h2")
                    else :
                        if event.port == 3 or event.port == 4:
                            install_fwdrule(event,packet,1) 
                            log.debug("no video service go low band")
                        else:
                            if ippkt.dstip == '10.0.0.1':
                                install_fwdrule(event,packet,3) 
                                log.debug("go to h1")
                            else:
                                install_fwdrule(event,packet,4) 
                                log.debug("go to h2")
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
                    if ippkt.dstip == '10.0.0.3':
                        install_fwdrule(event,packet,3) 
                        log.debug("go to h3")
                    elif ippkt.dstip == '10.0.0.4':
                        install_fwdrule(event,packet,4) 
                        log.debug("go to h4")
                    elif tcpp.srcport == 1880:
                        install_fwdrule(event,packet,2) 
                        log.debug("go to s3")
                    else :
                        install_fwdrule(event,packet,1) 
                        log.debug("go to s2")


        # flood, but don't install the rule
        def flood (message = None):
            """ Floods the packet """
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
        '''
        Add your logic here for firewall application
        '''
def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Video Slicing module
    '''
    core.registerNew(VideoSlice)
