#!/usr/bin/env python

"""
Source:
http://code.google.com/p/minidns/source/browse/minidns
"""

"""
Header
  7  6  5  4  3  2  1  0  7  6  5  4  3  2  1  0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Query
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

ResourceRecord
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
|                                               |
/                     RDATA                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Source: http://doc-tcpip.org/Dns/named.dns.message.html
"""

"""
prevent aTV update
Source: http://forum.xbmc.org/showthread.php?tid=93604

loopback to 127.0.0.1...
  mesu.apple.com
  appldnld.apple.com
  appldnld.apple.com.edgesuite.net
"""


import sys
import socket
import struct
from multiprocessing import Pipe  # inter process communication
import signal

import Settings
from Debug import *  # dprint()



"""
 Hostname/DNS conversion
 Hostname: 'Hello.World'
 DNSdata:  b'<len(Hello)>Hello<len(World)>World<NULL>'
"""
def HostToDNS(Host):
    DNSdata = b''
    for label in Host.split('.'):
        DNSdata += bytes([len(label)]) + label.encode('ascii')
    DNSdata += b'\x00'
    return DNSdata

def DNSToHost(DNSdata, i, followlink=True):
    Host = ''
    while DNSdata[i]!=0:
        nlen = DNSdata[i]
        if nlen & 0xC0:
            if followlink:
                Host = Host + DNSToHost(DNSdata, ((DNSdata[i] & 0x3F)<<8) + DNSdata[i+1] , True)+'.'
            break
        else:
            Host = Host + DNSdata[i+1:i+nlen+1].decode('ascii', 'replace')+'.'
            i+=nlen+1
    Host = Host[:-1]
    return Host



def printDNSdata(paket):
    # HEADER
    print("ID {0:04x}".format((paket[0]<<8)+paket[1]))
    print("flags {0:02x} {1:02x}".format(paket[2], paket[3]))
    print("OpCode "+str((paket[2]>>3)&0x0F))
    print("RCode "+str((paket[3]>>0)&0x0F))
    qdcount = (paket[4]<<8)+paket[5]
    ancount = (paket[6]<<8)+paket[7]
    nscount = (paket[8]<<8)+paket[9]
    arcount = (paket[10]<<8)+paket[11]
    print("Count - QD, AN, NS, AR:", qdcount, ancount, nscount, arcount)
    adr = 12

    # QDCOUNT (query)
    for i in range(qdcount):
        print("QUERY")
        host = DNSToHost(paket, adr)

        adr = adr + len(host) + 2
        print(host)
        print("type "+str((paket[adr+0]<<8)+paket[adr+1]))
        print("class "+str((paket[adr+2]<<8)+paket[adr+3]))
        adr = adr + 4

    # ANCOUNT (resource record)
    for i in range(ancount):
        print("ANSWER")
        print(paket[adr])
        if paket[adr] & 0xC0:
            print("link")
            adr = adr + 2
        else:
            host = DNSToHost(paket, adr)
            adr = adr + len(host) + 2
        print(host)
        _type = (paket[adr+0]<<8)+paket[adr+1]
        _class = (paket[adr+2]<<8)+paket[adr+3]
        print("type, class: ", _type, _class)
        adr = adr + 4
        print("ttl")
        adr = adr + 4
        rdlength = (paket[adr+0]<<8)+paket[adr+1]
        print("rdlength", rdlength)
        adr = adr + 2
        if _type==1:
            print("IP:", end=' ')
            for j in range(rdlength):
                print(paket[adr+j], end=' ')
            print()
        elif _type==5:
            print("redirect:", DNSToHost(paket, adr))
        else:
            print("type unsupported:", end=' ')
            for j in range(rdlength):
                print(paket[adr+j], end=' ')
            print()
        adr = adr + rdlength

def printDNSdata_raw(DNSdata):
    # hex code
    for i in range(len(DNSdata)):
        if i % 16==0:
            print()
        print("{0:02x}".format(DNSdata[i]), end=' ')
    print()

    # printable characters
    for i in range(len(DNSdata)):
        if i % 16==0:
            print()
        if (DNSdata[i]>32) & (DNSdata[i]<128):
            print(chr(DNSdata[i]), end=' ')
        else:
            print(".", end=' ')
    print()



def parseDNSdata(paket):
    
    def getWord(DNSdata, addr):
        return (DNSdata[addr]<<8)+DNSdata[addr+1]
    
    DNSstruct = {}
    adr = 0
    
    # header
    DNSstruct['head'] = { \
                    'id': getWord(paket, adr+0), \
                    'flags': getWord(paket, adr+2), \
                    'qdcnt': getWord(paket, adr+4), \
                    'ancnt': getWord(paket, adr+6), \
                    'nscnt': getWord(paket, adr+8), \
                    'arcnt': getWord(paket, adr+10) }
    adr = adr + 12
    
    # query
    DNSstruct['query'] = []
    for i in range(DNSstruct['head']['qdcnt']):
        DNSstruct['query'].append({})
        host_nolink = DNSToHost(paket, adr, followlink=False)
        host_link = DNSToHost(paket, adr, followlink=True)
        DNSstruct['query'][i]['host'] = host_link
        adr = adr + len(host_nolink)+2
        DNSstruct['query'][i]['type'] = getWord(paket, adr+0)
        DNSstruct['query'][i]['class'] = getWord(paket, adr+2)
        adr = adr + 4
    
    # resource records
    DNSstruct['resrc'] = []
    for i in range(DNSstruct['head']['ancnt'] + DNSstruct['head']['nscnt'] + DNSstruct['head']['arcnt']):
        DNSstruct['resrc'].append({})
        host_nolink = DNSToHost(paket, adr, followlink=False)
        host_link = DNSToHost(paket, adr, followlink=True)
        DNSstruct['resrc'][i]['host'] = host_link
        adr = adr + len(host_nolink)+2
        DNSstruct['resrc'][i]['type'] = getWord(paket, adr+0)
        DNSstruct['resrc'][i]['class'] = getWord(paket, adr+2)
        DNSstruct['resrc'][i]['ttl'] = (getWord(paket, adr+4)<<16)+getWord(paket, adr+6)
        DNSstruct['resrc'][i]['rdlen'] = getWord(paket, adr+8)
        adr = adr + 10
        DNSstruct['resrc'][i]['rdata'] = []
        if DNSstruct['resrc'][i]['type']==5:  # 5=redirect, evaluate name
            host = DNSToHost(paket, adr, followlink=True)
            DNSstruct['resrc'][i]['rdata'] = host
            adr = adr + DNSstruct['resrc'][i]['rdlen']
            DNSstruct['resrc'][i]['rdlen'] = len(host)
        else:  # 1=IP, ...
            for j in range(DNSstruct['resrc'][i]['rdlen']):
                DNSstruct['resrc'][i]['rdata'].append( paket[adr+j] )
            adr = adr + DNSstruct['resrc'][i]['rdlen']
    
    return DNSstruct

def encodeDNSstruct(DNSstruct):
    
    def appendWord(DNSdata, val):
        DNSdata.append((val>>8) & 0xFF)
        DNSdata.append( val     & 0xFF)
    
    DNS = bytearray()
    
    # header
    appendWord(DNS, DNSstruct['head']['id'])
    appendWord(DNS, DNSstruct['head']['flags'])
    appendWord(DNS, DNSstruct['head']['qdcnt'])
    appendWord(DNS, DNSstruct['head']['ancnt'])
    appendWord(DNS, DNSstruct['head']['nscnt'])
    appendWord(DNS, DNSstruct['head']['arcnt'])
    
    # query
    for i in range(DNSstruct['head']['qdcnt']):
        host = HostToDNS(DNSstruct['query'][i]['host'])
        DNS.extend(bytearray(host))
        appendWord(DNS, DNSstruct['query'][i]['type'])
        appendWord(DNS, DNSstruct['query'][i]['class'])
        
    # resource records
    for i in range(DNSstruct['head']['ancnt'] + DNSstruct['head']['nscnt'] + DNSstruct['head']['arcnt']):
        host = HostToDNS(DNSstruct['resrc'][i]['host'])  # no 'packing'/link - todo?
        DNS.extend(bytearray(host))
        appendWord(DNS, DNSstruct['resrc'][i]['type'])
        appendWord(DNS, DNSstruct['resrc'][i]['class'])
        appendWord(DNS, (DNSstruct['resrc'][i]['ttl']>>16) & 0xFFFF)
        appendWord(DNS, (DNSstruct['resrc'][i]['ttl']    ) & 0xFFFF)
        appendWord(DNS, DNSstruct['resrc'][i]['rdlen'])
        
        if DNSstruct['resrc'][i]['type']==5:  # 5=redirect, hostname
            host = HostToDNS(DNSstruct['resrc'][i]['rdata'])
            DNS.extend(bytearray(host))
        else:
            DNS.extend(DNSstruct['resrc'][i]['rdata'])
    
    return DNS

def printDNSstruct(DNSstruct):
    for i in range(DNSstruct['head']['qdcnt']):
        print("query:", DNSstruct['query'][i]['host'])

    for i in range(DNSstruct['head']['ancnt'] + DNSstruct['head']['nscnt'] + DNSstruct['head']['arcnt']):
        print("resrc:", end=' ')
        print(DNSstruct['resrc'][i]['host'])
        if DNSstruct['resrc'][i]['type']==1:
            print("->IP:", end=' ')
            for j in range(DNSstruct['resrc'][i]['rdlen']):
                print(DNSstruct['resrc'][i]['rdata'][j], end=' ')
            print()
        elif DNSstruct['resrc'][i]['type']==5:
            print("->alias:", DNSstruct['resrc'][i]['rdata'])
        else:
            print("->unknown type")



def Run(cmdPipe, param):
    if not __name__ == '__main__':
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    dinit(__name__, param)  # init logging, DNSServer process
    
    cfg_IP_self = param['IP_self']
    cfg_Port_DNSServer = param['CSettings'].getSetting('port_dnsserver')
    cfg_IP_DNSMaster = param['CSettings'].getSetting('ip_dnsmaster')
    
    try:
        DNS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        DNS.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        DNS.settimeout(5.0)
        DNS.bind((cfg_IP_self, int(cfg_Port_DNSServer)))
    except Exception as e:
        dprint(__name__, 0, "Failed to create socket on UDP port {0}: {1}", cfg_Port_DNSServer, e)
        sys.exit(1)
    
    intercept = [param['HostToIntercept']]
    restrain = []

    if param['CSettings'].getSetting('use_custom_dns_bind_ip') == "True":
        cfg_IP_self = param['CSettings'].getSetting('custom_dns_bind_ip')
    else:
        cfg_IP_self = param['IP_self']

    if param['CSettings'].getSetting('intercept_atv_icon')=='True':
        intercept.append('a1.phobos.apple.com')
        dprint(__name__, 0, "Intercept Atv Icon: Enabled")
    if param['CSettings'].getSetting('prevent_atv_update')=='True':
        restrain = ['mesu.apple.com', 'appldnld.apple.com', 'appldnld.apple.com.edgesuite.net']
        dprint(__name__, 0, "Prevent Atv Update: Enabled")

    dprint(__name__, 0, "***")
    dprint(__name__, 0, "DNSServer: Serving DNS on {0} port {1}.", cfg_IP_self, cfg_Port_DNSServer)
    dprint(__name__, 1, "intercept: {0} => {1}", intercept, cfg_IP_self)
    dprint(__name__, 1, "restrain: {0} => 127.0.0.1", restrain)
    dprint(__name__, 1, "forward other to higher level DNS: "+cfg_IP_DNSMaster)
    dprint(__name__, 0, "***")
    
    try:
        while True:
            # check command
            if cmdPipe.poll():
                cmd = cmdPipe.recv()
                if cmd=='shutdown':
                    break
            
            # do your work (with timeout)
            try:
                data, addr = DNS.recvfrom(1024)
                dprint(__name__, 1, "DNS request received!")
                dprint(__name__, 1, "Source: "+str(addr))
                
                #print("incoming:")
                #printDNSdata(data)

                # analyse DNS request
                # todo: how about multi-query messages?
                opcode = (data[2] >> 3) & 0x0F # Opcode bits (query=0, inversequery=1, status=2)
                if opcode == 0:                     # Standard query
                    domain = DNSToHost(data, 12)
                    dprint(__name__, 1, "Domain: "+domain)

                paket=b''
                if domain in intercept:
                    dprint(__name__, 1, "***intercept request")
                    paket+=data[:2]         # 0:1 - ID
                    paket+=b"\x81\x80"      # 2:3 - flags
                    paket+=data[4:6]        # 4:5 - QDCOUNT - should be 1 for this code
                    paket+=data[4:6]        # 6:7 - ANCOUNT
                    paket+=b'\x00\x00'      # 8:9 - NSCOUNT
                    paket+=b'\x00\x00'      # 10:11 - ARCOUNT
                    paket+=data[12:]                                     # original query
                    paket+=b'\xc0\x0c'                                   # pointer to domain name/original query
                    paket+=b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'   # response type, ttl and resource data length -> 4 bytes
                    paket+=bytes(int(x) for x in cfg_IP_self.split('.')) # 4bytes of IP
                    dprint(__name__, 1, "-> DNS response: "+cfg_IP_self)

                elif domain in restrain:
                    dprint(__name__, 1, "***restrain request")
                    paket+=data[:2]         # 0:1 - ID
                    paket+=b"\x81\x80"      # 2:3 - flags
                    paket+=data[4:6]        # 4:5 - QDCOUNT - should be 1 for this code
                    paket+=data[4:6]        # 6:7 - ANCOUNT
                    paket+=b'\x00\x00'      # 8:9 - NSCOUNT
                    paket+=b'\x00\x00'      # 10:11 - ARCOUNT
                    paket+=data[12:]                                     # original query
                    paket+=b'\xc0\x0c'                                   # pointer to domain name/original query
                    paket+=b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'   # response type, ttl and resource data length -> 4 bytes
                    paket+=b'\x7f\x00\x00\x01'  # 4bytes of IP - 127.0.0.1, loopback
                    dprint(__name__, 1, "-> DNS response: "+cfg_IP_self)

                else:
                    dprint(__name__, 1, "***forward request")

                    try:
                        DNS_forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        DNS_forward.settimeout(5.0)
                    except Exception as e:
                        dprint(__name__, 0, "Failed to create socket for DNS_forward): {0}", e)
                        continue
                    
                    DNS_forward.sendto(data, (cfg_IP_DNSMaster, 53))
                    paket, addr_master = DNS_forward.recvfrom(1024)
                    DNS_forward.close()
                    # todo: double check: ID has to be the same!
                    # todo: spawn thread to wait in parallel
                    dprint(__name__, 1, "-> DNS response from higher level")
                
                #print("-> respond back:")
                #printDNSdata(paket)
                
                # todo: double check: ID has to be the same!
                DNS.sendto(paket, addr)
            
            except socket.timeout:
                pass
            
            except socket.error as e:
                dprint(__name__, 1, "Warning: DNS error ({0}): {1}", e.errno, e.strerror)
            
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # we heard you!
        dprint(__name__, 0, "^C received.")
    finally:
        dprint(__name__, 0, "Shutting down.")
        DNS.close()



if __name__ == '__main__':
    cmdPipe = Pipe()
    
    cfg = Settings.CSettings('.')
    param = {}
    param['CSettings'] = cfg

    param['IP_self'] = '192.168.178.20'  # IP_self?
    param['baseURL'] = 'http://'+ param['IP_self'] +':'+ cfg.getSetting('port_webserver')
    param['HostToIntercept'] = cfg.getSetting('hosttointercept')

    Run(cmdPipe[1], param)
