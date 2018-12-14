# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A shortest-path forwarding application.

This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.

You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.  However, this
does (mostly) work. :)

Depends on openflow.discovery
Works with openflow.spanning_tree
"""

#from colors import red,green,yellow
from colorama import Fore, Back, Style 
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
import time
import datetime
#from Mail_Handler import Mail
log = core.getLogger()
from pox.lib.util import dpidToStr
from pox.openflow.of_json import *
import math
#import test_flow_stat3
log = core.getLogger()
pointer = 0

# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.  (dpid,xid)->WaitingPath
waiting_paths = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 15
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

# How long is allowable to set up a path?
PATH_SETUP_TIME = 4

#keeps track of the number of flows until we reach 50
my_counter = 0


my_start = 0

#stores the IP destination for each flow so that the suspected
#attack destination could be identified
ipList = []

#saves the path for detecting the switches in the attack path
#when an attack is suspected
path_for_stat = []
#keeps track of the switches that a statistic request has been
#sent to. This is to prevent sending duplicate requests.
sent_sw = []
entropy_counter = 0
#The variable used as the entropy threshold.
Entc2 = 0
#The variable used as the receiving rate threshold.
frate_th = 20
frate2 = 0
attackswitch = {}

def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


def _check_path (p):
  """
  Make sure that a path is actually a string of nodes with connected ports

  returns True if path is valid
  """
  for a,b in zip(p[:-1],p[1:]):
    if adjacency[a[0]][b[0]] != a[2]:
      return False
    if adjacency[b[0]][a[0]] != b[2]:
      return False
  return True


def _get_path (src, dst, first_port, final_port):
  """
  Gets a cooked path -- a list of (node,in_port,out_port)
  """
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]

  # Now add the ports
  r = []
  in_port = first_port
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,in_port,out_port))
    in_port = adjacency[s2][s1]
  r.append((dst,in_port,final_port))

  assert _check_path(r), "Illegal path!"

  return r


class WaitingPath (object):
  """
  A path which is waiting for its path to be established
  """
  def __init__ (self, path, packet):
    """
    xids is a sequence of (dpid,xid)
    first_switch is the DPID where the packet came from
    packet is something that can be sent in a packet_out
    """
    self.expires_at = time.time() + PATH_SETUP_TIME
    self.path = path
    self.first_switch = path[0][0].dpid
    self.xids = set()
    self.packet = packet

    if len(waiting_paths) > 1000:
      WaitingPath.expire_waiting_paths()


  def add_xid (self, dpid, xid):
    self.xids.add((dpid,xid))
    waiting_paths[(dpid,xid)] = self



  @property
  def is_expired (self):
    return time.time() >= self.expires_at



  def notify (self, event):
    """
    Called when a barrier has been received
    """
    self.xids.discard((event.dpid,event.xid))
    if len(self.xids) == 0:
      # Done!
      if self.packet:
        log.debug("Sending delayed packet out %s"
                  % (dpid_to_str(self.first_switch),))
        msg = of.ofp_packet_out(data=self.packet,
            action=of.ofp_action_output(port=of.OFPP_TABLE))
        core.openflow.sendToDPID(self.first_switch, msg)

      core.l2_multi.raiseEvent(PathInstalled(self.path))


  @staticmethod
  def expire_waiting_paths ():
    packets = set(waiting_paths.values())
    killed = 0
    for p in packets:
      if p.is_expired:
        killed += 1
        for entry in p.xids:
          waiting_paths.pop(entry, None)
    if killed:
      log.error("%i paths failed to install" % (killed,))


class PathInstalled (Event):
  """
  Fired when a path is installed
  """
  def __init__ (self, path):
    self.path = path

class Cleanswitch (object):
  def __init__(self):
    pass  
  
  def _do_remove(self):
    t = time.time()
    if len(attackswitch) == 0:
      print (Fore.RED +'no switch under attack')
      return False
    else:
      for dpid, switch_ts in attackswitch.items():
        print (Fore.GREEN + 'checking the attack switch list')
        time_t = int(t - switch_ts)
        print time_t
        if time_t >= 12:
          print time_t
  
          del attackswitch[dpid]
          print 'Deleted switch from the attack list: %s', dpid
        if len(attackswitch) == 0:
          print (Fore.GREEN + 'Hurray We are Secure')
          return False
    return True  
  
  def _do_sleep(self):
    r = self._do_remove()
    if r == False:
      core.callDelayed(12, self._do_sleep)
    else:
      s = min(attackswitch, key=attackswitch.get)
      sleep_time = 12 - int(time.time() - attackswitch[s])
      core.callDelayed(sleep_time, self._do_sleep)  

class Switch (EventMixin):
  
  entDic = {} #Table for the IP address and its occurrence
  all_ip = {}
  dstEnt = [] #List of entropies
  count1 = 0
  start_time = 0
  end_time = 0
  ftimer = 0
  
  count3 = 0
  max_path = []
  Entth = 1
  Entc = 0
  
  @staticmethod
  def cleaning_sent_sw ():
    del sent_sw[:]
    print "deleting sent_sw"
  
  
  def statcolect(self, path_stat, element, element_src):
    global my_counter
    # my-counter : counts the number of packets. We collect 50 packet
    
    global ipList
    
    global my_start
    global entropy_counter
    global frate_th
    global frate2
    global Entc2
    print "Packet Counter:", my_counter

    #This function collects IP statistics
    ipList.append(element)

    #Increment until we reach 50
    
    if my_counter == 0:
      #we need to calculate the time it takes o collect 50
      #packets so we could use in calculating the rate
      self.start_time = time.time()
      my_start = self.start_time
      print "start time" ,my_start
    
    my_counter +=1
    
    #keep the path statistics so that we could find the switches
    #in the attack path when an attack is suspected    
    
    if element in self.all_ip:
      self.all_ip[element].append(path_stat)
    else:
      self.all_ip[element]= (path_stat)
    
    if my_counter == 50:    
      self.end_time = time.time()
      self.ftimer = self.end_time - my_start
      print "we reach 50 and our start_time %s end_time %s and timer is %s" % (str(my_start), str(self.end_time),str(self.ftimer))    
      
      self.start_time = 0
      self.entDic = {}
      
      for i in ipList:
        if i not in self.entDic:
          self.entDic[i] =0
        self.entDic[i] +=1
        
    
      #print the hash table and clear all
      print self.entDic
    
      max_ip = max(self.entDic, key=self.entDic.get)
      self.max_path = self.all_ip[max_ip]
    
      #call the entropy function
      self.Entc = self.entropy(self.entDic)
      print "Entc", self.Entc
      print "Entth", self.Entth       
      
      #using math.floor to compare the integer part of the entropies    
      if math.floor(self.Entc) >= math.floor(self.Entth):
        frate = 50 / self.ftimer
        frate2 = frate
        Entc2 = self.Entc
        print "frate2 is updated:",frate2
        
        if frate <= frate_th:
          print "Be happy frate<=frate_th frate= ",frate
          print "frate_th=",frate_th
          self.Entth  = self.Entc
          print "Entth updated to Entth=",self.Entth
          if frate >= 20:
            self.frate_th = frate
            print "frate_th updated to",frate_th
          frate = 0
          entropy_counter = 0
          print "entropy_counter reset to",entropy_counter
          self.count1 = 0
          self.ftimer = 0     
         
        else:
          self.count1 +=1
          print "frate=", frate  
          print "frate_th=",frate_th
          print "count1=",self.count1
          
          if self.count1 == 5:
            self.max_path = self.all_ip[max_ip]
            self.max_path = sorted(self.max_path)
            dedup = [self.max_path[i] for i in range(len(self.max_path)) if i == 0 or self.max_path[i] != self.max_path[i-1]]            
            dtm = datetime.datetime.now()
            msg = "Suspect an attack, querying switches" + " Time:" + str(dtm)            
            with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
              filep.write('\n')
              filep.write(msg)
              filep.write('\n')
            
            
            for raha in dedup:
              if type(raha) == type(list()):
                dtm = datetime.datetime.now()
                msg= "Switches suspected in the Attack path are:" +str(raha) +" Time:" + str(dtm)     
                with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
                  filep.write(msg)
                  filep,write("\n")
                
                print "The switches suspected of being in the Attack path are:", raha
                print ""
            
            for raha in dedup:
              if type(raha) == type(list()):
                self.flow_stat(raha)
            self.count1 = 0
            self.ftimer = 0
            frate = 0 
          
          else:
            self.ftimer = 0
            self.frate = 0
            
            
      else:
        self.count1 = 0
        self.ftimer = 0
        frate = 0
        entropy_counter +=1
        print "count3=",entropy_counter
       
        if entropy_counter == 5:
          self.max_path = self.all_ip[max_ip]
          self.max_path = sorted(self.max_path)
          dedup = [self.max_path[i] for i in range(len(self.max_path)) if i == 0 or self.max_path[i] != self.max_path[i-1]]            
          dtm = datetime.datetime.now()
          msg = "we suspect an attack because entropy_counter=5, we will query switches" + " Time:" + str(dtm)   
          
          with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
              filep.write('\n')
              filep.write(msg)
              filep.write('\n')
          for raha in dedup:
            if type(raha) == type(list()):
              dtm = datetime.datetime.now()
              msg= "The switches suspected of being in the Attack path are:" +str(raha) +" Time:" + str(dtm)                  
              with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:     
                filep.write("\n")
                filep.write(msg)
                filep.write("\n")
              print "The switches suspected of being in the Attack path are:", raha
              print ""                    
                
          for raha in dedup:
            if type(raha) == type(list()):
              self.flow_stat(raha)
          self.count1 = 0
          entropy_counter = 0
          self.ftimer = 0
          frate = 0
        self.entDic = {}
        ipList = []
        my_counter = 0    
        
                  
                  
        
 
  def entropy (self, lists):
    #this function computes entropy
    elist = []
    print lists.values()
    print sum(lists.values())
    for p in lists.values():
      print p
      c = float(p)/50
      print "c=",c
      elist.append(-c * math.log(c, 2))
    Ec = sum(elist)
    print 'Entropy = ',sum(elist)
    self.dstEnt.appe    
    
    
  # handler for timer function that sends the requests to the
  #switches in the attack path that a request is not sent to them
  #in the last 10 seconds.    
    
  def _timer_func (self, attack_p):
    sent_connection = 0
    for connection in core.openflow._connections.values():
      for item in attack_p:
        if dpidToStr(connection.dpid) == str(item[0]):
          if dpidToStr(connection.dpid) not in sent_sw:
            print"sending flow request to switch",dpidToStr(connection.dpid)
            dtm = datetime.datetime.now()
            msg= "Sending flow request to:"+dpidToStr(connection.dpid) + " Time:" + str(dtm)
            with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
              
              filep.write(msg)
              filep.write('\n')
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
            sent_connection +=1
            sent_sw.append(dpidToStr(connection.dpid))

    log.info("Sent %i flow stats request(s)", sent_connection)
    dtm = datetime.datetime.now()
    msg= "Sent Switches list:" +str(sent_sw) +" Time:" + str(dtm)
    with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
      filep.write(msg)
      filep.write('\n')
    print "sent switches",sent_sw
      


  def _handle_flowstats_received (self, event):
    global frate2
    global Entc2
    global frate_th
    stats = flow_stats_to_list(event.stats)
    log.info("FlowStatsReceived from %s",dpidToStr(event.connection.dpid))
    
    flowlist = []
    for flow in event.stats:
      flowlist.append({
      "table_id": flow.table_id,
      "duration_sec": flow.duration_sec,
      "duration_nsec": flow.duration_nsec,
      "idle_timeout": flow.idle_timeout,
      "hard_timeout": flow.hard_timeout,
      "packet_count": flow.packet_count,
      "byte_count": flow.byte_count,
      })
      
   # print flowlist
    count_flow = 1
    count_3 = 0
    for f in event.stats:
      count_2 = 0
      count_flow +=1
      if f.byte_count <20:
        count_2 +=1
      if f.packet_count <4:
        count_2 +=1      
        if ((f.duration_sec*pow(10,9)) + f.duration_nsec)<9999999999:   
          count_2 +=1
        if count_2 >=2:
          count_3 +=1
          
    rate = (float(count_3)/count_flow) * 100
    log.info("on switch %s: we have count_3 %s count_flow %s with a rate of %s percent",dpidToStr(event.connection.dpid), count_3, count_flow,
rate)
    if rate>87:
      dtm = datetime.datetime.now()
      msg = "There is an attack at switch :" 
      print(msg)
      dpidToStr(event.connection.dpid) + "with rate of:" + str(rate) +" Time: " + str(dtm)
      attackswitch[dpidToStr(event.connection.dpid)] =time.time()
    
      with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:
        filep.write(msg)
        filep.write('\n')
      frate_th = 20   
      Entth = 1
      print "frate_th is updated to:",frate_th
     
    else:
      self.Entth = Entc2
      frate_th = frate2
      print "frate_th is updated to",frate_th
      dtm = datetime.datetime.now()
      msg= "We didn't have an attack on switch" + dpidToStr(event.connection.dpid) + "rate=" +str(rate) + "and the  +\
      new entth=" +str(self.Entth) + "New frate_th=" +str(frate_th) + "Time:" + str(dtm)
      with open('/root/pox/pox/forwarding/logfile.txt','a+') as filep:      
        filep.write(msg)
        filep.write('\n')

  # main functiont to launch the module
  def flow_stat (self, attack):
    from pox.lib.recoco import Timer
    self._timer_func(attack)        
      
  
  def __init__ (self):
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None

  def __repr__ (self):
    return dpid_to_str(self.dpid)

  def _install (self, switch, in_port, out_port, match, buf = None):
    if len(attackswitch) == 0:
      FLOW_IDLE_TIMEOUT = 15
    else:
      FLOW_IDLE_TIMEOUT = 11      
      
    msg = of.ofp_flow_mod()
    msg.match = match
    msg.match.in_port = in_port
    msg.idle_timeout = FLOW_IDLE_TIMEOUT
    msg.hard_timeout = FLOW_HARD_TIMEOUT
    msg.actions.append(of.ofp_action_output(port = out_port))
    msg.buffer_id = buf
    switch.connection.send(msg)



  def _install_path (self, p, match, packet_in=None):
    wp = WaitingPath(p, packet_in)
    for sw,in_port,out_port in p:
      self._install(sw, in_port, out_port, match)
      msg = of.ofp_barrier_request()
      sw.connection.send(msg)
      wp.add_xid(sw.dpid,msg.xid)
      
      
      

  def install_path (self, dst_sw, last_port, match, event):
    """
    Attempts to install a path between this switch and some destination
    """
    p = _get_path(self, dst_sw, event.port, last_port)
    if p is None:
      log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)

      import pox.lib.packet as pkt

      if (match.dl_type == pkt.ethernet.IP_TYPE and
          event.parsed.find('ipv4')):
        # It's IP -- let's send a destination unreachable
        log.debug("Dest unreachable (%s -> %s)",
                  match.dl_src, match.dl_dst)

        from pox.lib.addresses import EthAddr
        e = pkt.ethernet()
        e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        e.dst = match.dl_src
        e.type = e.IP_TYPE
        ipp = pkt.ipv4()
        ipp.protocol = ipp.ICMP_PROTOCOL
        ipp.srcip = match.nw_dst #FIXME: Ridiculous
        ipp.dstip = match.nw_src
        icmp = pkt.icmp()
        icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        orig_ip = event.parsed.find('ipv4')

        d = orig_ip.pack()
        d = d[:orig_ip.hl * 4 + 8]
        import struct
        d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        icmp.payload = d
        ipp.payload = icmp
        e.payload = ipp
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = event.port))
        msg.data = e.pack()
        self.connection.send(msg)

      return

    log.debug("Installing path for %s -> %s %04x (%i hops)",
        match.dl_src, match.dl_dst, match.dl_type, len(p))

    print "dest ip is" , match.nw_dst
    send_path = p
    tuple(send_path)
    self.statcolect(send_path, match.nw_dst, match.nw_src)
    
    # We have a path -- install it
    self._install_path(p, match, event.ofp)

    # Now reverse it and install it backwards
    # (we'll just assume that will work)
    p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
    self._install_path(p, match.flip())
    

  def _handle_PacketIn (self, event):
    def flood ():
      """ Floods the packet """
      if self.is_holding_down:
        log.warning("Not flooding -- holddown active")
      msg = of.ofp_packet_out()
      # OFPP_FLOOD is optional; some switches may need OFPP_ALL
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop ():
      # Kill the buffer
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        event.ofp.buffer_id = None # Mark is dead
        msg.in_port = event.port
        self.connection.send(msg)

    packet = event.parsed

    loc = (self, event.port) # Place we saw this ethaddr
    oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

    if packet.effective_ethertype == packet.LLDP_TYPE:
      drop()
      return

    if oldloc is None:
      if packet.src.is_multicast == False:
        mac_map[packet.src] = loc # Learn position for ethaddr
        log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
    elif oldloc != loc:
      if loc[1] not in adjacency[loc[0]].values():
        log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                  dpid_to_str(oldloc[0].connection.dpid), oldloc[1],
                  dpid_to_str(   loc[0].connection.dpid),    loc[1])
        if packet.src.is_multicast == False:
          mac_map[packet.src] = loc # Learn position for ethaddr
          log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
      elif packet.dst.is_multicast == False:
        log.warning("Packet from %s to known destination %s arrived "
                    "at %s.%i without flow", packet.src, packet.dst,
                    dpid_to_str(self.dpid), event.port)        
      
      
    if packet.dst.is_multicast:
      log.debug("Flood multicast from %s", packet.src)
      flood()
    else:
      if packet.dst not in mac_map:
        log.debug("%s unknown -- flooding" % (packet.dst,))
        flood()
      else:
        dest = mac_map[packet.dst]
        match = of.ofp_match.from_packet(packet)
        self.install_path(dest[0], dest[1], match, event)

  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None

  def connect (self, connection):
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    log.debug("Connect %s" % (connection,))
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

  @property
  def is_holding_down (self):
    if self._connected_at is None: return True
    if time.time() - self._connected_at > FLOOD_HOLDDOWN:
      return False
    return True

  def _handle_ConnectionDown (self, event):
    self.disconnect()




class l2_multi (EventMixin):

  _eventMixin_events = set([
    PathInstalled,
  ])

  def __init__ (self):
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
    
    core.call_when_ready(startup,('openflow','openflow_discovery'))      
    


  def _handle_openflow_discovery_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches[l.dpid1]
    sw2 = switches[l.dpid2]
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        #if ll == event.link: continue
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break

    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

      bad_macs = set()
      for mac,(sw,port) in mac_map.iteritems():
        if sw is sw1 and port == l.port1: 
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
        if sw is sw2 and port == l.port2: 
          if mac not in bad_macs:
            log.debug("Unlearned %s", mac)
            bad_macs.add(mac)
      for mac in bad_macs:
        del mac_map[mac]
        
        


  def _handle_ConnectionUp (self, event):
    sw = switches.get(event.dpid)
    if sw is None:
      sw = Switch()
      switches[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)    
      


  def _handle_BarrierIn (self, event):
    wp = waiting_paths.pop((event.dpid,event.xid), None)
    if not wp:
      return
    wp.notify(event)      

  
  
def launch ():
  core.registerNew(l2_multi)
  core.registerNew(Cleanswitch)
  core.Cleanswitch._do_sleep()
  timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  Timer(timeout, WaitingPath.expire_waiting_paths,recurring=True)
  Timer(10, Switch.cleaning_sent_sw, recurring=True)
  core.openflow.addListenerByName("FlowStatsReceived",Switch()._handle_flowstats_received)  
  
  
  

