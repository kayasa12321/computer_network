#!/usr/bin/env python3


import struct
import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.LHS=1
        self.RHS=2
        self.SW=int(senderWindow)
        self.Length=int(length)
        self.Num=int(num)
        self.timeout=float(int(timeout)/1000)
        self.recvTimeout=float(int(recvTimeout)/1000)
        self.Total_TX_time = 0
        self.Number_of_reTX = 0
        self.Number_of_coarse_TOs = 0
        self.Throughput = 0
        self.Goodput = 0
        self.blasteeIPAddr =blasteeIp
        self.timecheck=time.time()
        self.first=time.time()
        self.final=time.time()
        self.ACKd=[0]*( int(num)+1)
        self.send_list=[0]*( int(num)+1)
        self.recent=0
        self.ackd=0
        self.state=0
        
        ...

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
       
        sequence = int.from_bytes(packet[3].to_bytes()[:4], 'big')
        self.send_list[sequence]=1
        if  self.ACKd[sequence]==0:#repeated packeet
            self.ackd+=1
            print("ackd",self.ackd)
        tmp4=self.LHS
        while tmp4<self.RHS:
            if self.ACKd[tmp4]==1:
                self.LHS+=1
                self.timecheck=time.time()
                self.state=0
                self.recent+=1        
            elif self.ACKd[tmp4]==0:
                break
            tmp4+=1
        log_debug("I got a packet")
    def make_pkt(self,sequence):
        my_pkt = Ethernet() + IPv4() + UDP()
        my_pkt[1].protocol = IPProtocol.UDP
        my_pkt[1].ttl =64
        my_pkt[0].ethertype = EtherType.IPv4
        my_pkt[0].src = "10:00:00:00:00:01"
        my_pkt[0].dst = "40:00:00:00:00:01"
        my_pkt[1].src = IPv4Address("192.168.100.1")
        my_pkt[1].dst = self.blasteeIPAddr
        my_pkt+=sequence.to_bytes(4,"big")
        my_pkt+=self.Length.to_bytes(2,"big")
        my_pkt+=(0).to_bytes(self.Length,'big')
        return my_pkt

    def handle_no_packet(self):
        log_debug("Didn't receive anything")

        # Creating the headers for the packet
        if (self.RHS - self.LHS < self.SW) and (self.RHS<=self.Num):
            self.RHS=min(self.LHS+self.SW,self.Num+1)
        if(time.time()-self.timecheck>self.timeout) and self.state==0:
            self.Number_of_coarse_TOs+=1
            print("need to recent ",self.Number_of_coarse_TOs)
            self.recent=self.LHS
            self.state=1
            for i in range(self.LHS,self.RHS):
                if self.send_list[i]==1 and self.ACKd[i]==0:
                    self.send_list[i]=2
            self.timecheck=time.time()
        if self.state==0:
            tmp1=self.LHS
            while tmp1<self.RHS:
                if self.send_list[tmp1]==0:
                    self.send_list[tmp1]=1
                    self.Goodput+=self.Length
                    self.Throughput+=self.Length
                    mypkt=self.make_pkt(tmp1)
                    self.net.send_packet("blaster-eth0",mypkt)
                    if tmp1==1:
                        self.start=time.time()
                    break
                tmp1+=1

        elif self.state==1:
            
            checkpoint=True# make sure all have been resend
            tmp3=self.recent
            while tmp3<self.RHS:
                if self.send_list[tmp3]==2:
                    mypkt=self.make_pkt(tmp3)
                    self.Number_of_reTX+=1
                    self.Throughput+=self.Length
                    self.net.send_packet("blaster-eth0",mypkt)
                    self.recent=tmp3+1
                    self.send_list[tmp3]=1
                    checkpoint=False
                    break
                tmp3+=1
            if checkpoint==True:
                self.state=0
       
        
      
        # Do other things here and send packet
        ...
    
    def print_list(self):
        self.Total_TX_time=self.final-self.start
        
   
        print("-------------------printing list-------------------")
        print("Total_TX_time:", self.Total_TX_time)
        print("Number_of_reTX:", self.Number_of_reTX)
        print("Number_of_coarse_TOs:", self.Number_of_coarse_TOs)
        print("Throughput:", self.Throughput/self.Total_TX_time)
        print("Goodput:", self.Goodput/self.Total_TX_time)
        print("----------------------------------------------------")

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while self.ackd<self.Num:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
        self.final=time.time()
        self.print_list()
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
