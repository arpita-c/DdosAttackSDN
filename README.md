# sdn-ddos

Preventing DDoS Attacks in SDN environments using entropy-based detection method.

## Purpose of different files

* flow_rate/ - Has code of flow based method
* detection.py - Has the actual code for entropy calculation and DDoS determination
* l3_learning_edited.py - l3 learning mode of POX controller with hooks into the entropy-based detection code
* launchAttack.py - Script which generates attack traffic
* launchTraffic.py - Script which generates normal traffic
* launchTrafficFast.py - Script to generate normal traffic but at faster rate

## Steps of execution

* Have a machine with Mininet, POX and Scapy installed. Mininet OVF file VM works the best

* Put the l3_learning_edited.py and detection.py in pox/pox/forwarding folder

* Launch the POX controller
```
python ./pox.py  forwarding.l3_learning_edited
```

* Launch the mininet topology
```
sudo mn --switch=ovsk --topo=tree,depth=2,fanout=7 --controller=remote,ip=127.0.0.1,port=6633
```

* You should see the switches connected to POX controller

* Start xterm terminals on a few hosts in mininet
```
mininet> xterm h1 h2 h3
```

* from the xterm terminals, run the launchTraffic.py and launchAttack.py scripts as follows:
```
python launchTraffic.py -s 2 -e 49
# Here, -s and -e specify the starting and ending octets of IPs starting with 10.0.0.x who we have to send packets to

```

```
python launchAttack.py 10.0.0.10
# Here, the only argument is the IP address of the host in the network we want to attack.
```

* See the drop in entropy values at POX terminal.