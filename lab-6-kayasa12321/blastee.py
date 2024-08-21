#!/usr/bin/env python3

import time

import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        self.blasteeIpaddr=IPv4Address("192.168.200.1")
        self.blasteeEthaddr="20:00:00:00:00:01"
        self.blasterIP=blasterIp
        self.num=num
        # TODO: store the parameters
        ...

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        mypkt = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()  
        mypkt[0].src=self.blasteeEthaddr
        mypkt[0].dst="40:00:00:00:00:02"
        mypkt[0].ethertype = EtherType.IPv4
        mypkt[1].dst=self.blasterIP
        mypkt[1].src=self.blasteeIpaddr
        mypkt[1].ttl=64
        mypkt[1].protocol=IPProtocol.UDP
        mypkt[2].src=4444
        mypkt[2].dst=5555
        
        
        #sequence = packet[3].to_bytes()[0:4]
        len_pay=int.from_bytes(packet[3].to_bytes()[4:6], 'big')
        if len_pay>=8:
            payload=packet[3].to_bytes()[6:14]
        else:
            
            payload=packet[3].to_bytes()[6:]+(0).to_bytes(8-len_pay,"big")
        
        mypkt+= packet[3].to_bytes()[0:4]
        mypkt+=payload
        
        self.net.send_packet( "blastee-eth0",mypkt)


    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
