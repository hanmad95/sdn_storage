#=====================================================================================================
# Network Storage Controller
#=====================================================================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
from operator import attrgetter
from collections import defaultdict
import ipaddress

# Added for link Discovery
import networkx as nx
from ryu.lib import hub
import time
import matplotlib.pyplot as plot
import numpy as np
from ryu.topology import api as topo_api
from ryu.topology import event as topo_event
from ryu import cfg

# Define Priorities and Timeouts
CONF = cfg.CONF
FLOW_DEFAULT_PRIO_FORWARDING = 10
CYCLE_FLOW_PRIO = 100
DOWNLOAD_PRIO = 150
TABLE_ROUTING = 0
FLOW_DEFAULT_IDLE_TIMEOUT = 200 

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        #For Upload and Download
        self.download_ip = "10.0.0.200"
        self.upload_ip = "10.0.0.240"
        self.data_ip = "10.0.0.250"
        self.download_file_ip = "10.0.0.220"
        self.topo_print_ip = "10.0.0.230"
        self.packet_loop_counter=0
        
        # for calculating the output ports for paths 
        self.host_to_switch=[]
        self.host_to_switchport=[]
        
        # for Database
        self.attr_incr = 0
        self.dummy_incr = 0
        self.file_attributes = []
        self.sample_ip = [10,0,0,50]
        
        #for Link Discovery
        self.name = 'LinkDiscovery'
        self.mac_to_port = {}
        self.ip_to_mac = {}
        
        # Variables for the network topology
        self.graph = nx.DiGraph()
        self.hosts = []
        self.links = []
        self.switches = []
        self.update_topo_thread = hub.spawn(self._print_topo)
        self.arp_checker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))
        
        
    #=========================================================
    #LINK DISCOVERY
    #=========================================================

    def find_longest_cycle(self):
        cycle = nx.simple_cycles(self.graph)
        print("Calculated Cycles:")
        cycles = list(cycle)
        print(cycles)

        #Pick Lingest Cycle:
        maxim=[]
        for k in cycles:
            maxim.append(len(k))
        self.longest_cycle = cycles[np.argmax(maxim)]

        print("Longest Cycle:")
        print(self.longest_cycle)

        #Test If Cycle is minimum 2 Switches
        if len(self.longest_cycle) <=1:
            print("Error: NO LOOP FOUND [MINIMUM TWO SWITCHES]")

        self.cycle_ports = []
        # Append all input and output ports
        for i in range(len(self.longest_cycle)):
            prev_switch_id = self.longest_cycle[(i-1)%len(self.longest_cycle)]
            current_switch_id = self.longest_cycle[(i)%len(self.longest_cycle)]
            next_switch_id = self.longest_cycle[(i+1)%len(self.longest_cycle)]

            for link in self.links:
                source = link[0]
                dest = link[1]
                if (source.dpid == prev_switch_id) and (dest.dpid == current_switch_id):
                    input_port = dest.port_no
                if (source.dpid == current_switch_id) and (dest.dpid == next_switch_id):
                    output_port = source.port_no
            temp = [input_port, output_port]
            self.cycle_ports.append(temp)
        return


    # Find shortest path from host towards the cycle
    def find_path_to_cycle(self,eth_src,mode):

        path_outports=[]

        # Find id of shortest switch
        for tupel in self.host_to_switch:
            if str(tupel[0])==str(eth_src):
                src_switch_id = tupel[1]
        counter = 0
        # Calculate all paths between
        for dest_switch_id in self.longest_cycle:
            path_tmp = nx.shortest_path(self.graph, src_switch_id, dest_switch_id, weight="load")
            if counter ==0:
                    path_to_cycle = path_tmp
            else:
                if len(path_to_cycle)>=len(path_tmp):
                        path_to_cycle=path_tmp
            counter = counter +1


        if mode == "download":
            #Reverse List:
            path_to_cycle = path_to_cycle[::-1]
            print("Path away from cylce:", path_to_cycle)
            list_length=len(path_to_cycle)
        else:
            print("Path towards cylce:", path_to_cycle)
            list_length=len(path_to_cycle)-1

        # Get the Ports for the list
        if list_length == 0 and mode=="upload":
                print("Upload with length 0")
                ind = self.longest_cycle.index(path_to_cycle[0])
                path_outports.append(self.cycle_ports[ind][1])

        elif list_length==1 and mode=="download":
            print("Download with lenght 1")
            for tupel in self.host_to_switchport:
                print("Tupel:", tupel, eth_src)
                if str(tupel[0])==str(eth_src):
                    output_port = int(tupel[1])
                    path_outports.append(output_port)


        elif list_length >=1 and mode =="upload":
            for k in range(list_length):
                current_switch_id = path_to_cycle[k%len(path_to_cycle)]
                next_switch_id = path_to_cycle[(k+1)%len(path_to_cycle)]

                for link in self.links:
                    source = link[0]
                    dest = link[1]
                    if (source.dpid == current_switch_id) and (dest.dpid == next_switch_id):
                        output_port = source.port_no
                        path_outports.append(output_port)

        elif list_length >1 and mode=="download":
            for k in range(list_length):
                current_switch_id = path_to_cycle[k%len(path_to_cycle)]
                next_switch_id = path_to_cycle[(k+1)%len(path_to_cycle)]

                for link in self.links:
                    source = link[0]
                    dest = link[1]
                    if (source.dpid == current_switch_id) and (dest.dpid == next_switch_id):
                        output_port = source.port_no
                        path_outports.append(output_port)
                        
            #Append Last Output_port
            for tupel in self.host_to_switchport:
                if str(tupel[0])==str(eth_src):
                    output_port = tupel[1]
                    path_outports.append(output_port)

        print("Path Ports:", path_outports)

        return path_to_cycle, path_outports

    # print for debugging
    def _print_topo(self):
        hub.sleep(15)
        while True:
            self.logger.info("Nodes: %s" % self.graph.nodes)
            self.logger.info("Edges: %s" % self.graph.edges)

            hub.sleep(10)


    # Handle new host 
    @set_ev_cls(topo_event.EventHostAdd)
    def new_host_handler(self, ev):
        host = ev.host
        self.logger.info("New %s detected", host)

        # Extract Switch ID
        switch = host.port.dpid
        # Extract Source Mac Address
        src = host.mac
        # Create source,dest tupel
        tupel_host_switch = [src,switch]
        tupel_host_switchport = [src,host.port.port_no]
        # Add node representing MAC of new host
        self.graph.add_node(src)
        # Add edges
        self.graph.add_edge(switch,src,weight=1,outport_src = host.port.port_no,load=1)
        self.graph.add_edge(src,switch,weight=1,outport_src = 0,load=1)
        self.host_to_switch.append(tupel_host_switch)
        self.host_to_switchport.append(tupel_host_switchport)
        
    # Handle new switch
    @set_ev_cls(topo_event.EventSwitchEnter)
    def new_switch_handler(self, ev):
        switch = ev.switch
        self.logger.info("New %s detected", switch)
        self.graph.add_node(switch.dp.id)
        self.switches.append(switch)
        
        
    # Handle new links 
    @set_ev_cls(topo_event.EventLinkAdd)
    def new_link_handler(self, ev):
        link = ev.link
        self.logger.info("New %s detected", link)
        entry1 = [link.src,link.dst]
        entry2 = [link.dst,link.src]
        if entry1 in self.links:
            pass
        else: 
            self.graph.add_edge(link.src.dpid,link.dst.dpid,weight=1,outport_src=link.src.port_no,load=1)
            self.graph.add_edge(link.dst.dpid,link.src.dpid,weight=1,outport_src=link.dst.port_no,load=1)
            self.links.append(entry1)
            self.links.append(entry2)

    #============================================================================
    # END OF LINK DISCOVERY
    #============================================================================

    def _reset_arp(self):
        hub.sleep(2)
        while True:
            self.arp_checker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))
            hub.sleep(2)

    # Add flows 
    def add_flow(self,datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle_timeout, priority=priority, match=match,
                                    actions=actions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    match=match, actions=actions)
        datapath.send_msg(mod)

    # Add flows for a given path towards or away from the cycle
    def add_flow_to_cycle(self,parser,mode,path,outports,net_dst,tcp_port):

        if mode == "upload":
            print("Add Flow Rules towards Cycle for Uploads")
            for k in range(len(path)-1):
                current_switch_id = path[k]
                match = parser.OFPMatch(dl_type=0x0800, nw_proto=17,nw_dst=net_dst,tp_dst=tcp_port)
                actions = [parser.OFPActionOutput(outports[k])]

                # Get Switch datapath
                for switch in self.switches:
                    if switch.dp.id == current_switch_id:
                        datapath = switch.dp

                self.add_flow(datapath,CYCLE_FLOW_PRIO,match,actions,None,FLOW_DEFAULT_IDLE_TIMEOUT)

        if mode == "download":
            # Reverse Path
            print("Add Flow Rules Away from Cycle for Downloads")
            for k in range(len(path)):
                current_switch_id = path[k]
                match = parser.OFPMatch(dl_type=0x0800, nw_proto=17,nw_dst=net_dst,tp_dst=tcp_port)
                actions = [parser.OFPActionOutput(outports[k])]

                # Get Switch datapath
                for switch in self.switches:
                    if switch.dp.id == current_switch_id:
                        datapath = switch.dp

                self.add_flow(datapath,DOWNLOAD_PRIO,match,actions,None,FLOW_DEFAULT_IDLE_TIMEOUT)
    
    # Add flows for a given cycle 
    def add_flow_for_cycle(self, parser, cycle_path, pkt, nw_src, nw_dest, dl_src, in_port,tcp_port):

        index = 0
        for switch_id in cycle_path: 
            self.logger.debug("Current Switch %s and ports: %s" % (switch_id, self.cycle_ports[index]))
            # Determine match and actions
            current_input_port = self.cycle_ports[index][0]
            current_output_port = self.cycle_ports[index][1]

            match = parser.OFPMatch(dl_type=0x0800, nw_proto=17,nw_dst=nw_dest,tp_dst=tcp_port)
            actions = [parser.OFPActionOutput(current_output_port)]

            # Get Switch datapath
            for switch in self.switches:
                if switch.dp.id == switch_id:
                    datapath = switch.dp

            self.add_flow(datapath, CYCLE_FLOW_PRIO, match, actions, None, FLOW_DEFAULT_IDLE_TIMEOUT)
            index = index +1

    # Send back ACK for an Uplaod Request 
    def send_ack(self, pkt_ethernet, pkt_icmp, pkt_ipv4, ofp_parser, msg,file_attributes):
        print("In send ACK",pkt_icmp.data, file_attributes)
        new_pkt = packet.Packet()
        new_pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src ))
        new_pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, proto=pkt_ipv4.proto))
        data = "ACK" + ";" + str(file_attributes[2]) + ";" + str(file_attributes[3])
        print("\n\n\n\n")
        print("   ")
        print("Ack data", data)
        pkt_icmp.data.data = data.encode()
        new_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0,data=pkt_icmp.data))
        new_pkt.serialize()
        print("newpack", new_pkt)
        data = new_pkt.data
        actions = [ofp_parser.OFPActionOutput(port=msg.in_port)]
        out = ofp_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER,
              actions=actions,data=data)
        msg.datapath.send_msg(out)

    # Send back ACK for a Download Request 
    def send_ack_download(self, pkt_ethernet, pkt_icmp, pkt_ipv4, ofp_parser, msg,ack_msg):
        print("\n\n\nIn send download ACK\n\n", ack_msg)
        new_pkt = packet.Packet()
        new_pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src ))
        new_pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, proto=pkt_ipv4.proto))
        if self.file_attributes:
            data = ack_msg + ";" + str(self.file_attributes)
        else:
            data = ack_msg
        print("data ack",data)
        pkt_icmp.data.data = data.encode()
        new_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0,data=pkt_icmp.data))
        new_pkt.serialize()
        data = new_pkt.data
        actions = [ofp_parser.OFPActionOutput(port=msg.in_port)]
        out = ofp_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.datapath.ofproto.OFP_NO_BUFFER, in_port=msg.datapath.ofproto.OFPP_CONTROLLER,
              actions=actions,data=data)
        msg.datapath.send_msg(out)

    
    # Handle incomming ipv4 packets 
    def _handle_ipv4(self, datapath, in_port, pkt, msg):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # extract headers from packet
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_data = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        eth_dst_in = eth.dst
        net_src = ipv4_data.src
        net_dst = ipv4_data.dst

        inside_attr = []
        if pkt_icmp:
            print("\n TCP pkt received",pkt_icmp,net_dst)

        # When packet is a Download Request 
        if net_dst == self.download_ip:
            print("Download Request")
            # Added by Sugandh:
            decoded_str = pkt_icmp.data.data.decode('UTF-8')
            print("decoded_str",decoded_str)
            if decoded_str == 'Download_Request;':
                if self.file_attributes:
                    self.send_ack_download(eth, pkt_icmp, ipv4_data, parser, msg,"ACK")
                else:
                    self.send_ack_download(eth, pkt_icmp, ipv4_data, parser, msg,"No files present in network to download")
            return
            
        # When packet is a Download File Request 
        if net_dst == self.download_file_ip:
            print("Downloading File")
            mode = "download"
                # 1.Calculate Longest Cycle
            print("Calculate longest Cycle:")
            self.find_longest_cycle()
                # 2.Find shortest Path away from Cycle
            print("Calculate Path to Cycle")
            path,outports = self.find_path_to_cycle(eth.src,mode)
            decoded_str =  pkt_icmp.data.data.decode('UTF-8')
            decoded_list = decoded_str.split(":")
            print("\n\nDECODED LIST",decoded_list)
            
            if decoded_list[0] == 'Download_File_Request':
                file_index = int(decoded_list[1]) - 1
                print("File_inda",file_index)
                print("File index",file_index,self.file_attributes[file_index][2],self.file_attributes[file_index][3])

                    # 3.Add Flows for Path from cycle to host
                print("Install Rules for Cycle")
                self.add_flow_to_cycle(parser,mode,path,outports,self.file_attributes[file_index][2],self.file_attributes[file_index][3])
                
                # 4. Remove the File from the Database
                print(self.file_attributes)
                del self.file_attributes[file_index] 
                self.attr_incr = self.attr_incr - 1

                print("Rules Installed")
            return
        
        # When packet is a Print Topo Request
        if net_dst == self.topo_print_ip:
            print("\nPrint Request\n")
            decoded_str = pkt_icmp.data.data.decode('UTF-8')
            decoded_list = decoded_str.split(":")
            if decoded_list[0] == 'Print_Request':
                
                print("Calculate longest Cycle:")
                self.find_longest_cycle()
                # Check if Loop is discovered
                print("Loop",self.longest_cycle)
                # Set Colors for the edges
                edgelist=[]
                for k in range(len(self.longest_cycle)):
                    edgelist.append((self.longest_cycle[k%len(self.longest_cycle)],self.longest_cycle[(k+1)%len(self.longest_cycle)]))
                pos = nx.spring_layout(self.graph)
                nx.draw_networkx_edges(self.graph,pos,edgelist,edge_color="r",width=4)
                    
                # Draw the Graph and Calculate Cycle
                nx.draw(self.graph,pos, with_labels=True)
                plot.draw()
                plot.show()
                #time.sleep(30)


        # Case of Upload Request
        if net_dst == self.upload_ip:
            print("Upload Request")
            mode = "upload"
            # 1.Calculate Cycle
            self.find_longest_cycle()
            # 2.Find the shortest path towards Cycle
            path,outports = self.find_path_to_cycle(eth.src,mode)
            # Importet by Sugandh:
            decoded_str = pkt_icmp.data.data.decode('UTF-8')
            decoded_list = decoded_str.split(":")
            print("\n",decoded_list[1])
            if decoded_list[0] == 'Upload_Request':

                inside_attr.append(decoded_list[1])
                self.file_attributes.append(inside_attr)
                self.file_attributes[self.attr_incr].append(round(float(decoded_list[2])))
                self.sample_ip[3] += 1
                new_ip = ipaddress.IPv4Address('10.0.0.50') + self.dummy_incr
                self.file_attributes[self.attr_incr].append(new_ip)
                new_port = 6001 + self.dummy_incr
                self.file_attributes[self.attr_incr].append(new_port)

                # Add Flows:
                inside_attr = []
                print("Install Rules for Cycle and Path to Cycle")
                # 3.Add flow Rules for this Cylce
                self.add_flow_for_cycle(parser,self.longest_cycle,pkt,net_src,new_ip,eth.src,in_port,new_port)
                # 4.Add Flows for Path towards cycle
                self.add_flow_to_cycle(parser,mode,path,outports,new_ip,new_port)
                print("Rules Installed")
                print("Sending ACK")
                self.send_ack(eth, pkt_icmp, ipv4_data, parser, msg,self.file_attributes[self.attr_incr])
                self.attr_incr +=1
                self.dummy_incr += 1

            return

    # Simple switch
    def _handle_simple_switch(self, datapath, in_port, pkt, buffer_id=None, eth_dst=None):

        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth_dst is None:
            eth_dst = eth.dst
        dl_src = eth.src
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        self.logger.debug("M2P: %s", self.mac_to_port)
        
        # learn mac address
        self.mac_to_port[dpid][dl_src] = in_port
        self.logger.debug("packet in %s %s %s %s", dpid, in_port, dl_src, eth_dst)

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        elif eth_dst == 'ff:ff:ff:ff:ff:ff':
            self.logger.info("Broadcast packet at %s %s %s", dpid, in_port, dl_src)
            out_port = ofproto.OFPP_FLOOD
        else:
            self.logger.debug("OutPort unknown, flooding packet %s %s %s %s", dpid, in_port, dl_src, eth_dst)
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, dl_dst=haddr_to_bin(eth_dst))

            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, FLOW_DEFAULT_PRIO_FORWARDING, match, actions, buffer_id,
                              FLOW_DEFAULT_IDLE_TIMEOUT)
            else:
                self.add_flow(datapath, FLOW_DEFAULT_PRIO_FORWARDING, match, actions, None,
                              FLOW_DEFAULT_IDLE_TIMEOUT)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = pkt.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # Handle all incomming packets and classify them
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
   
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.in_port

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        arp_header = pkt.get_protocol(arp.arp)
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        ipv6_header = 34525 
        if arp_header: 
            # Learn src ip to mac mapping and forward
            if arp_header.src_ip not in self.ip_to_mac:
                self.ip_to_mac[arp_header.src_ip] = arp_header.src_mac
            eth_dst = self.ip_to_mac.get(arp_header.dst_ip, None)
            arp_dst = arp_header.dst_ip
            arp_src = arp_header.src_ip
            current_switch = datapath.id
            # Check if ARP-package from arp_src to arp_dst already passed this switch.
            if self.arp_checker[current_switch][arp_src][arp_dst]:
                self.logger.debug("ARP package known and therefore dropped")
                return
            else:
                self.arp_checker[current_switch][arp_src][arp_dst] = 1
                self.logger.debug("Forwarding ARP to learn address, but dropping all consecutive packages.")
                self._handle_simple_switch(datapath, in_port, pkt, msg.buffer_id, eth_dst)
        elif ipv4_header:  # IP packet -> load balanced routing
            self._handle_ipv4(datapath, in_port, pkt,msg)
        elif ipv6_header:
            return
        else:
            self._handle_simple_switch(datapath, in_port, pkt, msg.buffer_id)
