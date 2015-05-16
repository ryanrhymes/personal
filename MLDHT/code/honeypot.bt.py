#!/usr/bin/env python
# 
# This script implements honeypot for BitTorrent protocol
#
# Liang Wang @ Dept. Computer Science, University of Helsinki
# 2011.10.05
#

import math
import os, sys
import re
import threading
import time
import struct
import socket, SocketServer
from array import array
from urllib2 import *
from util import *
from bencode import bencode, bdecode
from BTPMessage import *
from khash import *

DEBUG = True
UDP_TO = 5                     # UDP timeout in seconds.
HTTP_TO = 10                   # HTTP timeout in seconds
MAX_THREAD_NUM = 1000          # Max threads a producer can spawn

class Connection(object):
    def __init__(self, sock, addr):
        self._buffer = ""
        self.sock = sock
        self.addr = addr
        self.am_interested = False
        self.am_blocking = True
        self.peer_interested = False
        self.peer_blocking = True
        self.honeypot_name = ""
        pass

    def data_come_in(self, length):
        while True:
            try:
                #self.sock.settimeout(HTTP_TO)
                if length <= len(self._buffer):
                    message = self._buffer[:length]
                    self._buffer = self._buffer[length:]
                    return message
                else:
                    # Be careful of the zero-length message
                    b = self.sock.recv(2*20)
                    if not len(b):
                        raise Exception("Zero length message!")
                    else:
                        self._buffer += b
            except Exception, err:
                print "Exception:Connection.data_come_in():", err
                if self.sock:
                    self.sock.close()
                self.sock = None
                break  # It is better to disconnect
        pass


class Peer(object):
    def __init__(self, port):
        self.id = 'A'*20
        self.peerlist = dict()
        self.port = port
        self.honey = None
        pass

    def _peer_dict(self, host, port):
        d = {
            'conn': Connection(host, port),
            'azureus': False,
            'utorrent': False,
            'DHT': False,
            'DHT_PORT': None,
            'FAST_EXTENSION': False,
            'NAT_TRAVERSAL': False,
            'peerid': ""
            }
        return d

    def connect(self, host, port):
        """Set up the application layer communication channel"""
        if (host, port) not in self.peerlist:
            self.peerlist[(host, port)] = self._peer_dict(host, port)
        peer = self.peerlist[(host, port)]
        conn = peer['conn']
        sock = conn.connect()
        if not sock:
            return False
        # Send handshake
        self.send_handshake(sock)
        protocol = conn.data_come_in(1 + len(protocol_name))
        # Get peer's config
        reserved = conn.data_come_in(8)
        if ord(reserved[0]) & AZUREUS:
            peer['azureus'] = True
        if ord(reserved[5]) & UTORRENT:
            peer['utorrent'] = True
        if ord(reserved[7]) & DHT:
            peer['DHT'] = True
        if ord(reserved[7]) & FAST_EXTENSION:
            peer['FAST_EXTENSION'] = True
        if ord(reserved[7]) & NAT_TRAVERSAL:
            peer['NAT_TRAVERSAL'] = True
        # Get infohash
        infohash = conn.data_come_in(20)
        # Get peer id
        peer['peerid'] = conn.data_come_in(20)
        # Handshake finish!
        print peer
        # Send peer id, initiator has different behaviors from receiver, refer
        # to my master thesis.
        try:
            sock.settimeout(HTTP_TO)
            sock.sendall(self.id)
        except Exception, err:
            if DEBUG:
                print "Exception:Peer.connect():send_id:", err
        return True

    def send_handshake(self, sock):
        try:
            sock.settimeout(HTTP_TO)
            sock.sendall(''.join((chr(len(protocol_name)),
                                  protocol_name,
                                  FLAGS,
                                  self.metainfo.infohash)))
        except Exception, err:
            if DEBUG:
                print "Exception:Peer.send_handshake():", err
        pass

    def send_bitfield(self, sock):
        try:
            bf = self.bitfield.tostring()
            s = struct.pack(">qc%is" % (len(bf)), len(bf)+1, chr(5), bf)
            sock.settimeout(HTTP_TO)
            sock.sendall(s)
        except Exception, err:
            if DEBUG:
                print "Exception:Peer.send_bitfield():", err
        pass

    def got_message(self, msg, conn):
        t = msg[0]
        r = None
        if t == UTORRENT_MSG:
            print "UTORRENT_MSG"
        if t == CHOKE:
            print "CHOKE"
        elif t == UNCHOKE:
            print "UNCHOKE"
        elif t == INTERESTED:
            print "INTERESTED"
        elif t == NOT_INTERESTED:
            print "NOT_INTERESTED"
        elif t == HAVE:
            i = struct.unpack("!i", msg[1:])[0]
            print "HAVE", i
        elif t == BITFIELD:
            print "BITFIELD"
            self.calc_bitfield(msg[1:])
        elif t == REQUEST:
            print "REQUEST"
        elif t == CANCEL:
            print "CANCEL"
        elif t == PIECE:
            print "PIECE"
        elif t == PORT:
            print "PORT", struct.unpack("!H", msg[1:])[0]
            #self.peerlist[conn.addr]["DHT"] = True
            #self.peerlist[conn.addr]["DHT_PORT"] = struct.unpack("!H", msg[1:])[0]
        #elif t == SUGGEST_PORT:
        #    print "SUGGEST_PORT"
        elif t == HAVE_ALL:
            print "HAVE_ALL"
        elif t == HAVE_NONE:
            print "HAVE_NONE"
        elif t == REJECT_REQUEST:
            print "REJECT_REQUEST"
        elif t == ALLOWED_FAST:
            print "ALLOWED FAST"
        elif t == UTORRENT_MSG:
            ext_type = ord(msg[1])
            d = bdecode(msg[2:])
            print "?"*10, d
            infodict = bencode(self.honey[self.honey.keys()[0]])
            response = {"msg_type": ord(chr(1)), "piece":d["piece"], "total_size":16*2**10}
            response = chr(20) + chr(conn.ut_metadata) + bencode(response) + infodict[d["piece"]*2**14: (d["piece"]+1)*2**14]
            response = struct.pack("!i", len(response)) + response
            print response[:300]
            conn.sock.sendall(response)
        else:
            print "got unknown message", repr(msg)
        # Continue
        return r

    def calc_bitfield(self, bitfield):
        p = 0
        for x in bitfield:
            for i in range(8):
                if (ord(x)>>i)&0x1:
                    p += 1
        print "I have %i pieces" % p
        pass

    def probe_incoming_peer(self, sock, addr):
        try:
            ipeer = {}
            conn = Connection(sock, addr)
            sock.settimeout(HTTP_TO)
            # Get peer's BT protocol
            pstrlen = ord(conn.data_come_in(1))
            ipeer['protocol'] = conn.data_come_in(pstrlen)
            print pstrlen, ipeer['protocol']
            # Get peer's config
            reserved = conn.data_come_in(8)
            if ord(reserved[0]) & AZUREUS:
                ipeer['azureus'] = True
            if ord(reserved[5]) & UTORRENT:
                ipeer['utorrent'] = True
            if ord(reserved[7]) & DHT:
                ipeer['DHT'] = True
            if ord(reserved[7]) & FAST_EXTENSION:
                ipeer['FAST_EXTENSION'] = True
            if ord(reserved[7]) & NAT_TRAVERSAL:
                ipeer['NAT_TRAVERSAL'] = True
            # Get peer's infohash
            ipeer['infohash'] = conn.data_come_in(20)
            # Send my handshake
            sock.sendall(''.join((chr(len(protocol_name)),
                                  protocol_name,
                                  FLAGS,
                                  ipeer['infohash'],
                                  self.id)))
            # Get peer id
            ipeer['peerid'] = conn.data_come_in(20)
            print "1$"*50
            if ipeer['infohash'] in self.honey.keys():
                print "<>" * 50, repr(conn._buffer)
            print "2$"*50, ipeer
            # Record the infohash
            self.log.write( "%s\t%s\t%s\n" % (str(addr),time.ctime(),intify(ipeer["infohash"])) )
            self.log.flush()

            # Get extension message
            if ipeer['utorrent']:
                response = {'m': {'ut_pex': ord(UTORRENT_MSG_PEX), "ut_metadata": ord(chr(3)), "metadata_size": 49152},
                            'v': ('%s %s' % ("utorrent", "3.01")).encode('utf8'),
                            'e': 0,
                            'p': self.port
                            }
                response = chr(20) + chr(0) + bencode(response)
                response = struct.pack("!i", len(response)) + response
                sock.sendall(response)
                print "3$"*50
                pstrlen = struct.unpack("!i", conn.data_come_in(4))[0]
                msg = conn.data_come_in(pstrlen)
                print "&"*10, pstrlen, len(msg)
                #msg = bdecode(msg[1:])
                assert(ord(msg[0])==20)
                assert(ord(msg[1])==0)
                msg = bdecode(msg[2:])
                conn.ut_metadata = msg['m']['ut_metadata']
                print msg
                self.log.write( "%s\t%s\t%s\n" % (str(addr),time.ctime(),str(msg)) )
                self.log.flush()
                print "4$"*50
            # Handshake finish!
            print ipeer
            self.log.write( "%s\t%s\t%s\n" % (str(addr),time.ctime(),str(ipeer)) )
            self.log.flush()

            while True:
                l = conn.data_come_in(4)
                l = struct.unpack("!i", l)[0]
                msg = conn.data_come_in(l)
                print l, repr(msg[0])
                self.log.write( "%s\t%s\t%s\t%s\n" % (str(addr),time.ctime(),repr(msg[0]),repr(msg[1])) )
                self.log.flush()
                self.got_message(msg, conn)
        except Exception, err:
            if DEBUG:
                print "Exception:Peer.probe_incoming_peer():", err
        pass

    def start_listen(self):
        timestamp = time.strftime("%Y%m%d%H%M%S")
        self.log = open("honeypot.bt.%s.%s.log" % (self.honeypot_name, timestamp), "a")
        isock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        isock.bind( ("", self.port) )
        isock.listen(5)
        while True:
            try:
                conn, addr = isock.accept()
                print addr
                #if addr[0] == "50.18.3.51" or addr[0] == "184.72.3.99":
                #    continue
                self.log.write( "%s\t%s\tconnect\n" % (str(addr),time.ctime()) )
                self.probe_incoming_peer(conn, addr)
                self.log.flush()
            except Exception, err:
                print "Exception:Peer.start_listen():", err
        self.log.close()
        pass

    def test(self):
        self.probe_all()
        pass

if __name__=="__main__":
    peer = Peer(30909)
    peer.start_listen()

    pass
