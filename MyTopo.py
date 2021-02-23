# -*- coding: utf-8 -*-
"""
hos1t -- switch1 - switch2--  switch3 --  host2 -- switch4 - switch1
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo(Topo):
    #"Simple topology example"
    def __init__(self):
        #"Create Custom Topo"
        Topo.__init__(self)
        delays = '100ms'
        leftHost = self.addHost("h1")
        rightHost = self.addHost("h2")
        firstSwitch = self.addSwitch("s1")
        secondSwitch = self.addSwitch("s2")
        thirdSwitch = self.addSwitch("s3")
        fourthSwitch = self.addSwitch("s4")

        self.addLink(leftHost, firstSwitch,cls=TCLink,delay=delays)
        self.addLink(firstSwitch,secondSwitch,cls=TCLink,delay=delays)
        self.addLink(secondSwitch, thirdSwitch,cls=TCLink,delay=delays)
        self.addLink(thirdSwitch,rightHost,cls=TCLink,delay=delays)
        self.addLink(thirdSwitch, fourthSwitch,cls=TCLink,delay=delays)
        self.addLink(fourthSwitch,firstSwitch,cls=TCLink,delay=delays)

topos = {"mytopo": (lambda: MyTopo())}
