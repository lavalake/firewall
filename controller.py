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
from collections import namedtuple
from csv import DictReader

log = core.getLogger()
Policy = namedtuple('Policy', ('src', 'dst'))
policyFile =  "%s/pox/firewall-policies.csv" % os.environ[ 'HOME' ]

class VideoSlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        tcpp = event.parsed.find('tcp')

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
                flood()
                return
                '''

                Add your logic here to slice the network

                '''
        # flood, but don't install the rule
        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        forward()

    def _handle_ConnectionUp(self, event):
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        '''
        Add your logic here for firewall application
        '''
        policies = self.read_policies(policyFile)
        for policy in policies.itervalues():
            log.debug("~~> Source Mac is %s", policy.src)
            log.debug("~~> Destination Mac is %s", policy.dst)

            match = of.ofp_match(dl_src = policy.src, dl_dst = policy.dst)

            # install the mods to block matches
            fm = of.ofp_flow_mod()
            fm.priority = 20  
            fm.match = match
            event.connection.send(fm)

            log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))
            

    def read_policies(self, file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")
            
            policies = {}
            for row in reader:
                policies[row['id']] = Policy(EthAddr(row['mac_0']), EthAddr(row['mac_1']))
                print policies[row['id']]
        return policies

def launch():
    
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Video Slicing module
    '''
    core.registerNew(VideoSlice)

