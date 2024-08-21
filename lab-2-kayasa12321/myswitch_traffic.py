'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    Table={}
    num=0
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
        if  Table.get(eth.src)!=None :
            if Table[eth.src ][0]!=fromIface:
                Table[eth.src]=[fromIface,num]
        if  Table.get(eth.src)==None :#add it to the table
                if  len(Table)>=5:
                    temp=None
                    for key in Table:
                        if temp==None:
                            temp=key
                        if Table[key][1]<Table[temp][1]:
                            temp=key
                    Table.pop(temp)
                Table[eth.src]=[fromIface,num]
        if eth.dst in mymacs:                      
            log_info("Received a packet intended for me")
        else:
           
            if eth.dst=='ff:ff:ff:ff:ff:ff'  or Table.get(eth.dst)==None  :  #broadcast
               #Table[eth.src]=fromIface
                 for intf in my_interfaces:
                     if fromIface!= intf.name:
                         log_info (f"Flooding packet {packet} to {intf.name}")
                         net.send_packet(intf, packet)
            else:#in
                 log_info (f"Flooding packet {packet} to {Table[eth.dst][0]}")
                 net.send_packet(Table[eth.dst][0], packet)
                 Table[eth.dst][1]=Table[eth.dst][1]+1

    net.shutdown()
