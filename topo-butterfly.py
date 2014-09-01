#! /usr/bin/python

"""Custom topology butterfly 

					 ---- s2 ---------s8---s6 --- h2
				   /	   \			   /
	h1 --- s1 ---			 - s4 --- s5 --
				   \	   /			   \		
		   h4  -----s3	--------s9---------- s7 --- h3
								|_h5
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mybutterfly' from the command line.
"""

import sys
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, OVSKernelSwitch, RemoteController
from mininet.link import TCIntf
from mininet.util import dumpNodeConnections, custom
from mininet.log import setLogLevel

class MyButterfly( Topo ):
	"Butterfly topology example."

	def __init__( self ):
		"Create custom topo."

		# Initialize topology
		Topo.__init__( self )

		# Add hosts and switches
		hosts = [0]
		for h in range(5):
			hosts.append(self.addHost('h%s' %(h + 1) ))
		switches = [0]
		for s in range(9):
			switches.append(self.addSwitch('s%s' %(s + 1) ))

		# Add links
		self.addLink(hosts[1], switches[1] )
		self.addLink(switches[1], switches[2] )
		self.addLink(switches[1], switches[3] )
		self.addLink(switches[2], switches[8] )
		self.addLink(switches[8], switches[6] )
		self.addLink(switches[2], switches[4] )
		self.addLink(switches[3], switches[4] )
		self.addLink(switches[3], switches[9] )
		self.addLink(switches[9], switches[7] )
		self.addLink(switches[4], switches[5] )
		self.addLink(switches[5], switches[6] )
		self.addLink(switches[5], switches[7] )
		self.addLink(hosts[2], switches[6] )
		self.addLink(hosts[3], switches[7] )
		"""
		"""
		self.addLink(hosts[4], switches[3] )
		self.addLink(hosts[5], switches[9] )

topos = { 'mybutterfly': ( lambda: MyButterfly() ) }

def setHostforMulticast():
	"Create butterfly network for Network Coding"
	intf = custom(TCIntf, bw=10)
	host = custom(CPULimitedHost, cpu=.1)
	topo = MyButterfly()
	if len(sys.argv) == 3 and sys.argv[1] == 'limit'  :
		if sys.argv[2] == 'link':
			net = Mininet(topo=topo, intf=intf, controller=RemoteController)
		elif sys.argv[2] == 'all':
			net = Mininet(topo=topo, host=host, intf=intf, controller=RemoteController)
		else:
			print 'wrong args!'
			raise Exception
	else :
		net = Mininet(topo=topo, controller=RemoteController)

	for h in range(5):
		host = net.nameToNode['h%s' %(h + 1)]
		host.cmd('route add -net 224.0.0.0/8 dev h%s-eth0' %(h + 1))
		"""    
	print "Dumping host connections"
	dumpNodeConnections(net.hosts)
	print "Testing network connectivity"
	net.pingAll()
	print "Testing multicast support"
	host = net.get('h1')
	host.cmd('ping -c1 224.0.1.64')
		"""
	if len(sys.argv) == 2 and sys.argv[1] == 'test' :
		net.start()
		host = net.get('h1')
		host.cmd('bash /home/lsch/mytest/test-ofctl.sh')
		host.cmd('iperf -c 224.0.1.10 -l 1016 -u -b 10K -t 6')
		net.stop()
	else:
		net.run(CLI, net)

if __name__ == '__main__':
	setLogLevel('info')
	setHostforMulticast()
