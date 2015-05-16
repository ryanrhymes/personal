#!/usr/bin/env python
# 
# This script is experimental.
#
# Liang Wang @ Dept. Computer Science, University of Helsinki
# 2011.09.20
#

import os, sys
import socket
import pickle
import Queue
import random
import time
import threading
import resource

from khash import *
from bencode import bencode, bdecode
from common import *

CTTIME = 10

class Crawler(object):
    def __init__(self, id = None):
        self.noisy = True                                       # Output extra info or not
        self.id = id if id else newID()                         # Injector's ID
        self.ip = get_myip()                                    # my ip
        self.port = get_port(30000, 31000)                      # my listening port
        self.krpc = KRPC()                                      # Simple KRPC translator
        self.nodePool = {}                                      # Dict of the nodes collected
        self.addrPool = {}                                      # Dict uses <ip,port> as its key
        self.nodeQueue = Queue.Queue(0)                         # Queue of the nodes to scan
        self.counter = CTTIME                                   # How long to wait after a queue is empty
        self.startTime = time.time()                            # Time start the crawler
        self.duplicates = 0                                     # How many duplicates among returned nodes
        self.total = 1                                          # Total number of returned nodes
        self.respondent = 0                                     # Number of respondent
        self.tn = 0                                             # Number of nodes in a specified n-bit zone
        self.tnold = 0
        self.tntold = 0
        self.tnspeed = 0

        self.isock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.isock.bind( ("",self.port) )
        self.isock_lock = threading.Lock()
        pass

    def ping(self, host, port):
        msg = self.krpc.encodeReq("ping", {"id":self.id})
        Transport(host, port, msg, self.dataComeIn).start()
        pass

    def findNode(self, host, port, target):
        msg = self.krpc.encodeReq("find_node", {"id":self.id, "target":target})
        self.isock.sendto(msg, (host,port))
        pass

    def processNodes(self, nodes):
        timestamp = time.time()
        for node in nodes:
            id = node["id"]
            node["timestamp"] = timestamp
            node["rtt"] = float('inf')
            if id not in self.nodePool:
                self.nodePool[id] = [node]
                self.convergeSpeed(node)
                if id != self.id:
                    self.nodeQueue.put(node)
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
        while self.counter:
            try:
                msg, addr = self.isock.recvfrom(PACKET_LEN)
                msgTID, msgType, msgContent = self.krpc.decodeRsp(msg)
                if "nodes" in msgContent:
                    self.processNodes(unpackNodes(msgContent["nodes"]))
                self.addrPool[addr] = {"timestamp":time.time()}
                self.respondent += 1
            except Exception, err:
                print "Exception:Crawler.listener():", err
        pass

    def start_sender(self):
        while self.counter:
            try:
                node = self.nodeQueue.get(True)
                if (distance(self.id, node["id"])>>148)==0:
                    self.findNode(node["host"], node["port"], node["id"])
                    for i in range(1,5):
                        tid = stringify(intify(node["id"]) ^ (2**(i*3) - 1))
                        self.findNode(node["host"], node["port"], tid)
                # This threshold can be tuned, maybe use self.respondent
                elif self.tn < 2000:
                    self.findNode(node["host"], node["port"], self.id)
            except Exception, err:
                print "Exception:Crawler.start_sender()", err, node
        pass

    def start_crawl(self):
        t1 = threading.Thread(target=self.start_listener, args=())
        t1.daemon = True
        t1.start()
        t2 = threading.Thread(target=self.start_sender, args=())
        t2.daemon = True
        t2.start()

        while self.counter:
            try:
                self.counter = CTTIME if self.nodeQueue.qsize() else self.counter-1
                self.info()
                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception, err:
                print "Exception:Crawler.start_crawl()", err
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

if __name__=="__main__":
    now = time.time()
    id = stringify(int(sys.argv[1])) if len(sys.argv)>1 else newID()
    crawler = Crawler(id)
    # Try to load local node cache
    try:
        if os.path.exists("nodecache"):
            nl = pickle.load(open("nodecache","r"))
            for n in nl:
                n["timestamp"] = time.time()
                n["rtt"] = float('inf')
                crawler.nodeQueue.put(n)
    except:
        pass
    # Try to get bootstrap nodes from official router
    crawler.findNode("router.bittorrent.com", 6881, crawler.id)
    crawler.start_crawl()
    print "%.2f minutes" % ((time.time() - now)/60.0)
    crawler.serialize()
    pass
