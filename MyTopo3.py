# -*- coding: utf-8 -*-
"""
Incresed Top
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo(Topo):
    #"Simple topology example"
    def __init__(self):
        #"Create Custom Topo"
        Topo.__init__(self)
        self.delays="50ms"
        leftHost = self.addHost("h1")
        rightHost = self.addHost("h2")
        Switch_1 = self.addSwitch("s1")
        Switch_2 = self.addSwitch("s2")
        Switch_3 = self.addSwitch("s3")
        Switch_4 = self.addSwitch("s4")
        Switch_5 = self.addSwitch("s5")
        Switch_6 = self.addSwitch("s6")
        Switch_7 = self.addSwitch("s7")
        Switch_8 = self.addSwitch("s8")

        self.addLink(leftHost, Switch_1,cls=TCLink,delay=self.delays)
        self.addLink(Switch_1, Switch_2,cls=TCLink,delay=self.delays)    
        self.addLink(Switch_2, Switch_3,cls=TCLink,delay=self.delays)
        self.addLink(Switch_3, Switch_4,cls=TCLink,delay=self.delays)
        self.addLink(Switch_4, Switch_5,cls=TCLink,delay=self.delays)
        self.addLink(Switch_5, Switch_6,cls=TCLink,delay=self.delays)
        self.addLink(Switch_6, Switch_7,cls=TCLink,delay=self.delays)
        self.addLink(Switch_7, Switch_8,cls=TCLink,delay=self.delays)
        self.addLink(Switch_8, Switch_3,cls=TCLink,delay=self.delays)   
        self.addLink(Switch_1, rightHost,cls=TCLink,delay=self.delays)
        

topos = {"mytopo": (lambda: MyTopo())}
