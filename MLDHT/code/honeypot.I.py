#!/usr/bin/env python
# 
# This script is an experimental honeypot.
#
# Liang Wang @ Dept. Computer Science, University of Helsinki, Finland
# 2011.10.03
#

import os
import sys
import socket
import pickle
import time
import threading
import resource

from honeypot_bt import *
from khash import *
from bencode import bencode, bdecode
from common import *
from multiprocessing import *

BUCKET_LIMIT = 8
HONEYPOT_NAME = "TEST"

class Honeypot(object):
    def __init__(self, id = None):
        self._debug = False                                     # Output extra info or not
        self.id = id if id else newID()                         # Honeypot's ID
        self.ip = get_myip()                                    # my ip
        self.port = get_port()                                  # my listening port
        self.btport = self.port + 0                             # The port running BT protocol
        self.krpc = KRPC()                                      # Simple KRPC translator
        self.buckets = []                                       # Bucket structure holding the known nodes
        self.nodePool = {}                                      # Dict of the nodes collected
        self.addrPool = {}                                      # Dict uses <ip,port> as its key
        self.nodeQueue = Queue(0)                               # Queue of the nodes to scan
        self.counter = 5                                        # How long to wait after a queue is empty
        self.startTime = time.time()                            # Time start the honeypot
        self.duplicates = 0                                     # How many duplicates among returned nodes
        self.total = 1                                          # Total number of returned nodes
        self.respondent = 0                                     # Number of respondent
        self.honey = []                                         # Honey used to lure our prey
        self.tn = 0                                             # Number of nodes in a specified n-bit zone
        self.tnold = 0
        self.tntold = 0
        self.tnspeed = 0
        self.ndist = 2**160-1

        self.isock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.isock.bind( ("",self.port) )
        self.isock_lock = threading.Lock()
        pass

    def add_to_bucket(self, node):
        """Add a node into the bucket, the interval is like this [x,y)"""
        if not len(self.buckets):
            self.buckets = [ [[0,2**160], []] ]
        id = intify(node["id"])
        bucket = None
        # Find the proper bucket for the now node
        for x in self.buckets:
            r, nl = x
            if id >= r[0] and id < r[1]:
                bucket = x
                break
        # OK, find the bucket for the new node
        if bucket:
            r, nl = bucket
            # If the bucket id full
            if len(nl) >= BUCKET_LIMIT:
                # if the new node 'near to me'?
                if self.is_in_bucket(self.id, bucket):
                    # split the bucket
                    x, y = r
                    m = ((y-x)>>1) + x
                    new_bucket = [ [x,m], [] ]
                    bucket[0] = [m,y]
                    pos = self.buckets.index(bucket)
                    self.buckets.insert(pos, new_bucket)
                    for n in nl:
                        tid = intify(n["id"])
                        if tid < m:
                            nl.remove(n)
                            new_bucket[1].append(n)
                    # Recursion
                    self.add_to_bucket(node)
                    pass
                # if the node is far from me and the bucket if full, drop it.
                else:
                    pass
            # OK, we have spare place for new nodes.
            else:
                nl.append(node)
        pass

    def remove_from_bucket(self, id, buckets):
        """Remove a node from a bucket"""
        bucket = self.in_which_bucket(id, buckets)
        node = self.is_in_bucket(id, bucket)
        bucket[1].remove(node)
        # if the bucket is empty, then merge with others
        if len(bucket[1])==0 and len(buckets)>1:
            x, y = bucket[0]
            pos = buckets.index(bucket)
            prev = max(pos-1,0)
            next = min(pos+1,len(buckets)-1)
            px, py = buckets[prev][0]
            nx, ny = buckets[next][0]
            if pos==prev or ( pos!=prev and (ny-nx)==(y-x) ):
                buckets[next][0] = [x,ny]
            elif pos==next or ( pos!=next and (py-px)==(y-x) ):
                buckets[prev][0] = [px,y]
            buckets.remove(bucket)
        pass

    def is_in_bucket(self, id, bucket):
        """Given the id and the bucket, check if the id is in the bucket"""
        node = None
        r, nl = bucket
        for n in nl:
            if id == n['id']:
                node = n
                break
        return node

    def in_which_bucket(self, id, buckets):
        """Given the id, check which bucket it is in"""
        b = None
        for bucket in buckets:
            if self.is_in_bucket(id, bucket):
                b = bucket
                break
        return b

    def bootstrap(self):
        """Bootstrap myself"""
        self.add_to_bucket({"id":self.id, "host":self.ip, "port":self.port})
        self.findNode("router.bittorrent.com", 6881, self.id)
        # Try to boot from local nodecache
        if os.path.exists("nodescache"):
            nl = pickle.load(open("nodescache","r"))
            for n in nl:
                self.findNode(n["host"], n["port"], self.id)
        pass

    def nearest(self, target, nl, limit=None):
        """Given the node list and the target id, return the nearest ones."""
        l= []
        for n in nl:
            l += [(distance(n["id"], target), n)]
        l.sort()
        m = [ n[1] for n in l[:limit] ]
        return m

    def ping(self, host, port):
        mtid = 3
        args = {"id":self.id}
        d = {TID : chr(mtid), TYP : REQ,  REQ : "ping", ARG : args}
        msg = self.krpc.encodeMsg(d)
        self.sendMsg(msg, (host,port))
        pass

    def findNode(self, host, port, target):
        mtid = 5
        args = {"id":self.id, "target":target}
        d = {TID : chr(mtid), TYP : REQ,  REQ : "find_node", ARG : args}
        msg = self.krpc.encodeMsg(d)
        self.sendMsg(msg, (host,port))
        pass

    def announcePeer(self, host, port, infohash, token, mtid=None):
        mtid = 7 if mtid==None else mtid
        args = {"id":self.id, "info_hash":infohash, "port":self.port, "token":token}
        d = {TID : chr(mtid), TYP : REQ,  REQ : "announce_peer", ARG : args}
        msg = self.krpc.encodeMsg(d)
        self.sendMsg(msg, (host,port))
        pass

    def getPeers(self, host, port, infohash, mtid=None):
        mtid = 11 if mtid==None else mtid
        args = {"id":self.id, "info_hash":infohash}
        d = {TID : chr(mtid), TYP : REQ,  REQ : "get_peers", ARG : args}
        msg = self.krpc.encodeMsg(d)
        self.sendMsg(msg, (host,port))
        pass

    def processNodes(self, nodes):
        timestamp = time.time()
        nodes = self.nearest(self.id, nodes)
        for node in nodes:
            id = node["id"]
            node["timestamp"] = timestamp
            node["rtt"] = float('inf')
            if id not in self.nodePool:
                self.nodePool[id] = [node]
                self.convergeSpeed(node)
                if id != self.id:
                    self.findNode(node["host"], node["port"], self.id)
                    for i in range(len(self.honey)):
                        # Liang: Test purpose
                        #if node["host"] == "50.18.3.51" or node["host"] == "184.72.3.99":
                        #    print "*"*50, node["host"], node["port"]
                        if True:
                            infohash = self.honey[i]
                            self.getPeers(node["host"], node["port"], infohash, i)
            else:
                if not self.hasNode(node["id"], node["host"], node["port"])\
                       and id != self.id:
                    self.nodePool[id].append(node)
                else:
                    self.duplicates += 1
            self.total += 1
        pass

    def hasNode(self, id, host, port):
        r = None
        for n in self.nodePool[id]:
            if n["host"] == host and n["port"] == port:
                r = n
                break
        return r

    def handle_find_node(self, tid):
        tid = intify(tid)
        bucket = None
        for x in self.buckets:
            r, nl = x
            if tid >= r[0] and tid < r[1]:
                bucket = x
                break
        return bucket[1]

    def sendMsg(self, msg, addr):
        """Send the message through isock, thread safe"""
        self.isock_lock.acquire()
        try:
            self.isock.sendto(msg, addr)
        except Exception, err:
            if self._debug:
                print "Exception:Honeypot.sendMsg():", err, addr
            pass
        self.isock_lock.release()
        pass

    def serialize(self):
        obj = {}
        for k, nlist in self.nodePool.items():
            for v in nlist:
                addr = (v['host'], v['port'])
                if addr in self.addrPool:
                    v["rtt"] = self.addrPool[addr]["timestamp"]- v["timestamp"]
                obj[k] = obj.get(k, []) + [v]

        timestamp = time.strftime("%Y%m%d%H%M%S")
        f = open("nodes.%s.%s" % (timestamp, str(intify(self.id))), "w")
        pickle.Pickler(f).dump(obj)
        f.close()
        pass

    def start_listener(self):
        """Process all the incomming messages here"""
        timestamp = time.strftime("%Y%m%d%H%M%S")
        log = open("honeypot.%s.%s.log" % (HONEYPOT_NAME, timestamp), "a")
        while True:
            try:
                msg, addr = self.isock.recvfrom(PACKET_LEN)
                d = None
                d = self.krpc.decodeMsg(msg)
                ts = time.time()

                # Liang: for test purpose
                func_s = ""
                if d["TYP"] == REQ:
                    func_s = d["MSG"]
                #if d["TYP"] == RSP and "nodes" not in d["MSG"]:
                #    print d
                if self._debug:
                    print time.ctime(), addr, d["TYP"], func_s #, d["MSG"], d["ARG"]

                # Add to bucket if it is a new node, otherwise update it.
                tid = d["MSG"]["id"] if d["TYP"] == RSP else d["ARG"]["id"]
                bucket = self.in_which_bucket(tid, self.buckets)
                if bucket:
                    pass
                else:
                    n = {"id":tid, "host":addr[0], "port":addr[1], \
                         "timestamp":ts, "lastupdate":ts}
                    self.add_to_bucket(n)
                # Process message according to their message type
                if d["TYP"] == RSP:
                    if "nodes" in d["MSG"]:
                        tdist = distance(self.id, d["MSG"]["id"])
                        if tdist < self.ndist:
                            self.ndist = tdist
                            self.processNodes(unpackNodes(d["MSG"]["nodes"]))
                            #print tdist, "+"*100
                        elif self.respondent < 100000:
                            self.processNodes(unpackNodes(d["MSG"]["nodes"]))
                    if "token" in d["MSG"]:
                        trans_id = ord(d["TID"])
                        infohash = self.honey[trans_id]
                        token = d["MSG"]["token"]
                        #self.announcePeer(addr[0], addr[1], infohash, token, trans_id)

                elif d["TYP"] == REQ:
                    #print addr, d["TID"], d["TYP"], d["MSG"], d["ARG"]
                    if "ping" == d["MSG"].lower():
                        rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id}}
                        rsp = self.krpc.encodeMsg(rsp)
                        self.sendMsg(rsp, addr)
                        pass
                    elif "find_node" == d["MSG"].lower():
                        nodes = self.handle_find_node(d["ARG"]["target"])
                        rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id}}
                        rsp[RSP]["nodes"] = packNodes(nodes)
                        rsp = self.krpc.encodeMsg(rsp)
                        self.sendMsg(rsp, addr)
                        pass
                    elif "get_peers" == d["MSG"].lower():
                        infohash = d["ARG"]["info_hash"]
                        # Liang: Hurray, catch U!
                        if infohash in self.honey and addr[0] != self.ip:
                            log.write("%s\tget_peers\t%i\n" % (str(addr),intify(infohash)))
                            print "+"*100, "get_peers", addr
                            infohash = d["ARG"]["info_hash"]
                            # lure the node to bt protocol
                            rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id, "token":"test"}}
                            rsp[RSP]["values"] = packPeers( [(self.ip,self.port)] )
                            rsp = self.krpc.encodeMsg(rsp)
                            #self.sendMsg(rsp, addr)
                            # Liang: Jump to individual talk now
                            # self.individual_talk(addr)
                        pass
                    elif "announce_peer" == d["MSG"].lower():
                        infohash = d["ARG"]["info_hash"]
                        if infohash in self.honey:
                            log.write("%s\tannounce_peer\n" % (str(addr)))
                            if self._debug:
                                print "-"*100, "announce_peer", addr
                        pass
                else:
                    pass
                #self.addrPool[addr] = {"timestamp":time.time()}
                self.respondent += 1
                log.flush()
            except Exception, err:
                if self._debug:
                    print "Exception:Honeypot.listener():", err, repr(msg)
                pass
        pass

    def individual_talk(self, taddr):
        while True:
            try:
                msg, addr = self.isock.recvfrom(PACKET_LEN)
                # ingore the irrelevant messages
                if addr != taddr:
                    continue

                d = self.krpc.decodeMsg(msg)
                ts = time.time()
                tid = d["MSG"]["id"] if d["TYP"] == RSP else d["ARG"]["id"]
                if self._debug:
                    print d

                # Process message according to their message type
                if d["TYP"] == RSP:
                    pass

                elif d["TYP"] == REQ:
                    if "ping" == d["MSG"].lower():
                        rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id}}
                        rsp = self.krpc.encodeMsg(rsp)
                        #self.sendMsg(rsp, addr)
                        pass
                    elif "find_node" == d["MSG"].lower():
                        nodes = self.handle_find_node(d["ARG"]["target"])
                        rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id}}
                        rsp[RSP]["nodes"] = packNodes(nodes)
                        rsp = self.krpc.encodeMsg(rsp)
                        #self.sendMsg(rsp, addr)
                        pass
                    elif "get_peers" == d["MSG"].lower():
                        infohash = d["ARG"]["info_hash"]
                        rsp = {TID:d["TID"], TYP:RSP, RSP:{"id":self.id, "token":"test"}}
                        rsp[RSP]["values"] = packPeers( [(self.ip,self.btport)] )
                        rsp = self.krpc.encodeMsg(rsp)
                        self.sendMsg(rsp, addr)
                        pass
                    elif "announce_peer" == d["MSG"].lower():
                        infohash = d["ARG"]["info_hash"]
                        if infohash in self.honey:
                            print "-"*100, "announce_peer", addr
                        pass
                else:
                    pass
            except Exception, err:
                if self._debug:
                    print "Exception:Honeypot.individual_talk():", err, repr(msg)
                pass
        sys.exit(0)
        pass

    def start_sender(self):
        while True:
            try:
                now = time.time()
                # Re-populate myself every 5 minutes
                if int(now)%300==0:
                    self.nodePool = {}
                    self.buckets = []
                    self.respondent = 0
                    self.bootstrap()
                time.sleep(1)
                pass
            except Exception, err:
                if self._debug:
                    print "Exception:Honeypot.start_sender()", err
        pass

    def start(self):
        t1 = threading.Thread(target=self.start_listener, args=())
        t1.daemon = True
        t1.start()
        t2 = threading.Thread(target=self.start_sender, args=())
        t2.daemon = True
        t2.start()
        peer = Peer(self.btport)
        peer.honey = self.honey
        t3 = threading.Thread(target=peer.start_listen, args=())
        t3.daemon = True
        t3.start()
        # Liang: test purpose
        self.test_184()

        self.bootstrap()
        while True:
            try:
                #self.info()
                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception, err:
                if self._debug:
                    print "Exception:Honeypot.start_crawl()", err
        pass

    def info(self):
        print "[NodeSet]:%i\t\t[12-bit Zone]:%i [%i/s]\t\t[Response]:%.2f%%\t\t[Queue]:%i\t\t[Dup]:%.2f%%" % \
              (len(self.nodePool), self.tn, self.tnspeed,
               self.respondent*100.0/max(1,len(self.nodePool)),
               self.nodeQueue.qsize(), self.duplicates*100.0/self.total)
        pass

    def convergeSpeed(self,node):
        if (distance(self.id, node["id"])>>148)==0:
            self.tn += 1
        if (time.time()-self.tntold) >= 5:
            self.tnspeed = int((self.tn-self.tnold)/(time.time()-self.tntold))
            self.tnold = self.tn
            self.tntold = time.time()
        pass

    def test_bucket(self):
        self.bootstrap()
        id_set = set()
        print "Add"
        for i in range(50000):
            id = newID()
            node = {"id":id}
            self.add_to_bucket(node)
            id_set.add(id)
        for x in self.buckets:
            print len(x[1])

        print "Remove"
        for id in id_set:
            if self.in_which_bucket(id, self.buckets):
                self.remove_from_bucket(id, self.buckets)
                pass
        for x in self.buckets:
            print len(x[1])

        pass

    def test_184(self):
        for i in range(len(self.honey)):
            infohash = self.honey[i]
            for j in range(500):
                print "getPeer", repr(infohash)
                self.getPeers("50.18.3.51", 11000+j, infohash, i)
        pass

def start_injecting(id):
    """Start all the honeypots"""
    honeypot = Honeypot(id)
    honeypot.start()
    pass

def create_fake_info(self):
    info = {}
    info["name"] = "Rise.of.the.Planet.of.the.Apes.2011.dvdrip.XviD-NOVA.avi"
    info["length"] = 1468095404
    info["piece length"] = 2**20
    info["pieces"] = "".join([ newID() for i in range(math.ceil(info["length"]*1.0/info["piece length"])) ])
    return info


if __name__=="__main__":
    now = time.time()
    #id = stringify(long(sys.argv[1])) if len(sys.argv)>1 else newID()
    id  = intify(newID())
    honey = [ stringify(id+i) for i in range(1, 11) ]
    id  = stringify(id)
    honeypot = Honeypot(id)
    honeypot.honey = honey
    honeypot.start()

    print "%.2f minutes" % ((time.time() - now)/60.0)
    #honeypot.serialize()
    pass
