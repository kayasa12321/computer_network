'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
from  collections import OrderedDict



def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    order_table=OrderedDict()

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
        if eth.dst in mymacs:
            if order_table.get(eth.src)!=None :
                order_table.pop(eth.src)
                order_table[eth.src]=fromIface  #reorder
            else:
                if len(order_table)>=5:
                    order_table.popitem(last=False)
                    order_table[eth.src]=fromIface
                else:
                    order_table[eth.src]=fromIface
            log_info("Received a packet intended for me")
        else:
            if order_table.get(eth.src)!=None :
                order_table.pop(eth.src)
                order_table[eth.src]=fromIface
            else:
                if  len(order_table)>=5:
                    order_table.popitem(last=False)
                    order_table[eth.src]=fromIface
                else:
                    order_table[eth.src]=fromIface   #add src
            if  order_table.get(eth.dst)==None or eth.dst=='ff:ff:ff:ff:ff:ff':   #condition   broadcast
              for intf in my_interfaces:
                if fromIface!= intf.name:
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)
            else:
                temp=order_table[eth.dst]
                order_table.pop(eth.dst)
                order_table[eth.dst]=temp   #renew the order
                log_info (f"Flooding packet {packet} to {order_table[eth.dst]}")
                net.send_packet(order_table[eth.dst], packet)



    net.shutdown()
