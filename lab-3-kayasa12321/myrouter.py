#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.my_inft=net.interfaces()
        self.my_table={}
       

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        for key in list(self.my_table):
            if time.time()-self.my_table[key][1]>=10:
                log_info(f"IP addr:{key}  MAC addr:{self.my_table[key][0]}  is  removed")
                self.my_table.pop(key)
        arp=packet.get_header(Arp)
        if arp is  None:
            log_info("not a  Arp packet")
        else:
            if arp.operation==1:
               
              
                for  inft in self.my_inft:
                    if arp.targetprotoaddr==inft.ipaddr:
                        self.my_table[arp.senderprotoaddr]=[arp.senderhwaddr,time.time()]
                        log_info(f"IP addr:{arp.senderprotoaddr}  MAC addr:{arp.senderhwaddr} is added  or refreshed\n")
                        reply_pkt=create_ip_arp_reply(inft.ethaddr,arp.senderhwaddr,inft.ipaddr,arp.senderprotoaddr)
                        self.net.send_packet(inft.name,reply_pkt)
            else:
                log_info("operation =2,it is a reply_packet")
        print("-------------------------------------------MAC_LIST-----------------------------------------------------\n")
        for key2 in list(self.my_table):
            print(f"IP addr:{key2}     MAC addr:{self.my_table[key2][0]}     time:{self.my_table[key2][1]}\n")

        ...

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
