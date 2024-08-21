#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        self.interfaces=net.interfaces()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            randnum = randint(1, 100)
            if(float(randnum)/100<=self.dropRate):
                log_info("drop the packet")
            else:
                for intf in self.interfaces :
                    if intf.name=="middlebox-eth1":
                        my_port=intf
                packet[Ethernet].src=my_port.ethaddr
                packet[Ethernet].dst="20:00:00:00:00:01"
                self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            for intf in self.interfaces :
                    if intf.name=="middlebox-eth0":
                        my_port=intf
            packet[Ethernet].src=  my_port.ethaddr
            packet[Ethernet].dst="10:00:00:00:00:01"
            self.net.send_packet("middlebox-eth0", packet)
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
