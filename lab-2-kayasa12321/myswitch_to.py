'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import time


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    Table={}
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        for key in list(Table.keys()):
            if(time.time()-Table[key][1]>10):
              Table.pop(key)
        if eth.dst in mymacs:
            Table[eth.src]=[fromIface,time.time()]
            log_info("Received a packet intended for me")
        
  
        else:
            Table[eth.src]=[fromIface,time.time()]
            if eth.dst=='ff:ff:ff:ff:ff:ff'  or  Table.get(eth.dst)==None  or Table[eth.dst][0]==fromIface : #broadcast
               #Table[eth.src]=fromIface
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                         log_info (f"Flooding packet {packet} to {intf.name}")
                         net.send_packet(intf, packet)
            else:#in
                 log_info (f"Flooding packet {packet} to {Table[eth.dst][0]}")
                 net.send_packet(Table[eth.dst][0], packet)

    net.shutdown()

