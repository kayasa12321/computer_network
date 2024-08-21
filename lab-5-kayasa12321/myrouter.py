#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.my_inft=net.interfaces()
        self.my_table = {}#缓存表
        self.forward_table={}#转发表
        self.waitinglist =[]#等待序列
        self.Todelete=[]#删除队列
        self.sendlist=[]#正在处理的IP队列，防止访问相同ip地址的操作同时出现
        self.erroricmplist=[]
        self.ARP_error=[]
        # other initialization stuff here

    def init_forward(self):
         for intf in self.my_inft :
            intf_ip=intf.ipaddr
            intf_mask=intf.netmask
            NextHop = '0.0.0.0'
            intf_port=intf.name
            prefix=IPv4Address(int(intf_ip)&int(intf_mask))
            net_addr=IPv4Network(str(prefix)+'/'+str(intf_mask))
            self.forward_table[net_addr]=[IPv4Address(NextHop),intf_port]
            file= open("forwarding_table.txt","r") 
            for line in file:
                temp = line.split()
                if temp:
                    self.forward_table[IPv4Network(temp[0]+'/'+temp[1])]=[temp[2],temp[3]]


    def handle_list(self,index):
        if self.waitinglist[index][5]==1 :
            icmp=self.waitinglist[index][0].get_header(ICMP)
            if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or icmp.icmptype==12):
                        return  1      
            return -1
        if self.waitinglist[index][2] in self.my_table.keys():#下一跳地址在arp缓存表内
            i = 0
            while i < len(self.sendlist):
                if self.sendlist[i]==self.waitinglist[index][2]:
                    del self.sendlist[i]
                i+=1
            self.waitinglist[index][0][0].dst = self.my_table[self.waitinglist[index][2]][0]
            self.net.send_packet(self.waitinglist[index][1].name,self.waitinglist[index][0])
            return 1
        elif time.time() -self.waitinglist[index][4]>1:#距离上次请求超过一个时间单位
         
            if self.waitinglist[index][3]<5:
                if self.waitinglist[index][3]==0:
                    tmp=0
                    while tmp < len(self.sendlist):
                        if self.sendlist[tmp]==self.waitinglist[index][2]:#判断对应ip地址是否已经在处理一个数据包
                             return 0
                        tmp += 1 
                    self.sendlist.append(self.waitinglist[index][2])
                etherheader = Ethernet(
                    src = self.waitinglist[index][1].ethaddr,
                    dst = "ff:ff:ff:ff:ff:ff",
                    ethertype = EtherType.ARP
                )
                arpheader = Arp(
                    operation = ArpOperation.Request,
                    senderhwaddr=self.waitinglist[index][1].ethaddr,
                    senderprotoaddr=self.waitinglist[index][1].ipaddr,
                    targethwaddr = "ff:ff:ff:ff:ff:ff",
                    targetprotoaddr = self.waitinglist[index][2]
                )
                packe = etherheader+arpheader
                #packe=create_ip_arp_request(self.waitinglist[index][1].ethaddr, self.waitinglist[index][1].ipaddr,self.waitinglist[index][2])
                self.net.send_packet(self.waitinglist[index][1].name,packe)
                self.waitinglist[index][3]+=1
                self.waitinglist[index][4]=time.time()
                return 0   #重新请求并更新状态
            else:
                tmp1 =0
                while tmp1 < len(self.sendlist):
                    if self.sendlist[tmp1]==self.waitinglist[index][2]:
                        del self.sendlist[tmp1]
                    tmp1+=1
                tmp2 =index+1
                while tmp2 <len(self.waitinglist):
                    if self.waitinglist[tmp2][2]==self.waitinglist[index][2]:
                        self.waitinglist[tmp2][5]=True
                    tmp2+=1
                icmp=self.waitinglist[index][0].get_header(ICMP)
                if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or  icmp.icmptype==12):
                        return  1        
                return -1
        else:
            return 0
        
    def  error_reply(self,origin_pkt,itype,icode,ifaceName):
        port1=self.net.interface_by_name(ifaceName)
        etherheader = Ethernet(
                    src = self.net.interface_by_name(ifaceName).ethaddr,
                    dst =origin_pkt[0].src,
                    ethertype = EtherType.IPv4)
        Ipv4header=IPv4(  )
        Ipv4header.dst=origin_pkt[1].src
        Ipv4header.src=port1.ipaddr
        Ipv4header.protocol=IPProtocol.ICMP
        Ipv4header.ttl=64
        ICMPheader=ICMP()
        ICMPheader.icmptype=itype
        ICMPheader .icmpcode=icode
        del origin_pkt[0]
        ICMPheader.icmpdata.data = origin_pkt.to_bytes()[:28]
        final_pkt=etherheader+Ipv4header+ICMPheader
        
        return  final_pkt


        
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        #TODO: your logic here
        for ip in list(self.my_table.keys()):#根据时间更新缓存表
             if time.time()-self.my_table[ip][1]>10000:
                  del self.my_table[ip]
        flagmax = True
        interfaces = self.net.interfaces()
        eth = packet.get_header(Ethernet)
        icmp=packet.get_header(ICMP)
        if eth.dst != "ff:ff:ff:ff:ff:ff" and self.net.interface_by_name(ifaceName).ethaddr != eth.dst:
            flagmax = False
        if flagmax:
            arp = packet.get_header(Arp)
        
            if arp and eth.ethertype == EtherType.ARP:# 判断其为以arp包，若无后面 and则会在1151卡住，会有个错误的使用了send_packet
                if arp.operation == 2 and arp.senderhwaddr != "ff:ff:ff:ff:ff:ff" :#回复包，更新arp表
                    for interface in interfaces:
                        if arp.targetprotoaddr == interface.ipaddr:
                            self.my_table[arp.senderprotoaddr]=(arp.senderhwaddr,time.time())
                if arp.operation ==1:#请求包，更新arp缓存表并且发送回复包
                    for interface1 in interfaces:
                        if arp.targetprotoaddr == interface1.ipaddr:    
                           self.my_table[arp.senderprotoaddr]=(arp.senderhwaddr,time.time())
                           reply_pac= create_ip_arp_reply(interface1.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                           self.net.send_packet(ifaceName,reply_pac)
                           break
            ipv4=packet.get_header(IPv4)
            if ipv4  and eth.ethertype==EtherType.IPv4 :
                flag=True
                
                #if packet[1].protocol != IPProtocol.ICMP and packet.get_header(ICMP)  is not None:
                 #   return 
                for interface in interfaces:
                    if packet[1].dst == interface.ipaddr:#目的地址为路由器接口，忽略
                       
#--------------------------------------------------------------------------------------------------------------------------------------------------
                        index3=packet.get_header_index(ICMP)
                        if packet[1].protocol==IPProtocol.ICMP and packet[index3].icmptype==8 and packet[index3].icmpcode==0:
                            reply_icmp=ICMP()
                            reply_icmp.icmpcode=packet[index3].icmpcode
                            reply_icmp.icmptype=0
                            reply_icmp.icmpdata.data=packet[index3].icmpdata.data
                            reply_icmp.icmpdata.identifier=packet[index3].icmpdata.identifier
                            reply_icmp.icmpdata.sequence=packet[index3].icmpdata.sequence                      #响应icmp回显请求
                            packet[2]=reply_icmp
                            packet[0].ethertype=EtherType.IPv4
                            packet[0].dst=packet[0].src
                            packet[0].src=interface.ethaddr
                            packet[1].dst=packet[1].src
                            packet[1].src=interface.ipaddr
                            packet[1].ttl = 64

                            break
                            
                           
#------------------------------------------------------------------------------------------------------------------------------------------------
                        else :
                            if  packet[1].src==self.net.interface_by_name(ifaceName).ipaddr  or  packet[1].protocol!=IPProtocol.ICMP:#
                                flag=0#
                                break
                            icmp=packet.get_header(ICMP)
                            if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or icmp.icmptype==12):
                                return        
                            packet=self.error_reply(packet,ICMPType.DestinationUnreachable,3,interface.name)                    #Q4
                            self.erroricmplist.append(packet)
                            
                            break
                            
                           
                if flag:
#-----------------------------------------------------------------------------------------------------------------------------------------------#
                    
                    maxlen = 0
                    for context in self.forward_table.keys():
                        if packet[1].dst in context:
                            if context.prefixlen > maxlen:                                           #在转发表中进行最大匹配
                                maxlen = context.prefixlen
                                text = self.forward_table[context]
#-------------------------------------------------------------------------------------------------------------------------------------------------#
                    if maxlen==0:
                        icmp=packet.get_header(ICMP)
                        if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or icmp.icmptype==12):
                            return        
                        packet=self.error_reply(packet,ICMPType.DestinationUnreachable,0,ifaceName)
                        self.erroricmplist.append(packet)
                        for context in self.forward_table.keys():
                            if packet[1].dst in context:
                                if context.prefixlen > maxlen:                                           #在转发表中进行最大匹配
                                    maxlen = context.prefixlen
                                    text = self.forward_table[context]
                        if  maxlen==0:
                            return 
                    if maxlen !=0:
                       
                        if packet[1].ttl <=1:
                            icmp=packet.get_header(ICMP)
                            if icmp is not None and (icmp.icmptype==3 or icmp.icmptype==11 or icmp.icmptype==12):
                                     return        
                            packet=self.error_reply(packet,ICMPType.TimeExceeded,0,ifaceName)
                            self.erroricmplist.append(packet)
                            len1=0
                            for context in self.forward_table.keys():
                               
                                if packet[1].dst in context:
                                    if context.prefixlen > len1:                                           #在转发表中进行最大匹配
                                        len1 = context.prefixlen
                                        text = self.forward_table[context]
                            if  len1 ==0:
                                return 
                        packet[1].ttl-=1
                               


                        
                        if text[0]!=IPv4Address('0.0.0.0'):#其为路由器上可到达的地址
                            nexthop = IPv4Address(text[0])
                        else:
                            nexthop = packet[1].dst#此时下一跳IP就期待为目的ip，直接填入packet[1].dst
                        name = text[1]
                        for interface in interfaces:
                            if interface.name == name:
                                packet[0].src = interface.ethaddr
                                if packet in self.erroricmplist:
                                    packet[IPv4].src=interface.ipaddr
                                    self.erroricmplist.remove(packet)
                                self.waitinglist.append([packet,interface,nexthop,0,0,False])  #分别表示数据包，对应接口，下一跳ip地址，请求次数，请求时间
                                break
                

                        
                        
    
    def clean_list(self):#根据时间更新缓存表对于缓存队列的表进行处理
        i = 0
        while i < len(self.waitinglist):
            flag = self.handle_list(i)
            if flag==1 :#已经成功发送，需要在队列中删除
                self.Todelete.append(i)
            elif flag== -1:
                self.Todelete.append(i)
                arp_error=self.error_reply(self.waitinglist[i][0],ICMPType.DestinationUnreachable,1,self.waitinglist[i][1].name)
                self.erroricmplist.append(arp_error)
                self.handle_packet((0,self.waitinglist[i][1].name,arp_error))
            i+=1
        n = len(self.Todelete)#对于处理完的和超过五次访问请求得要删除
        

        while n > 0:
            del self.waitinglist[self.Todelete[n-1]]
            del self.Todelete[n-1]
            n-=1



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        self.init_forward()
        while True:
            self.clean_list()
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


