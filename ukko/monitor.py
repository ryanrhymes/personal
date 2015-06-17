#!/usr/bin/env python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

#
# This script is modified based on center.py, and supports IPV4 UDP multicast.
# The script keeps listening the broadcasts from the nodes.
#
# Liang Wang @ Dept. of Computer Science, University of Helsinki, Finland
# Email: liang.wang [at] helsinki.fi
# 2011.03.07
#

import time
import os,sys
import struct
import pickle
import socket
import threading
import subprocess
import SocketServer
from multiprocessing import *

INCQUE = Queue(2**20)

class MyUDPServer(SocketServer.UDPServer):
    allow_reuse_address = True
    pass

class MyRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            data = pickle.loads(self.request[0].strip())
            #print "%s wrote:%s" % (self.client_address[0], data) # Remember to comment it out!!!
            INCQUE.put(data, False)
            socket = self.request[1]
            #socket.sendto("OK", self.client_address)
        except Exception, err:
            print "Exception:CentralServer.handle():", err

    def handle_error(self, request, client_address):
        print "Error:CentralServer.handle_error():", request

class MyListener(object):
    def __init__(self, mgrp=None, mport=None, register=False):
        #self.addr = (subprocess.Popen(["hostname","-I"], stdout=subprocess.PIPE).communicate()[0].split()[0], 1212)
        self.addr = (mgrp if mgrp else get_myip(), mport if mport else 1212)
        self.server = MyUDPServer(self.addr, MyRequestHandler)
        self.server.allow_reuse_address = True
        self.sock = socket.fromfd(self.server.fileno(), socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.regs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if register:
            t = threading.Thread(target=self.register_me, args=())
            t.daemon = True
            t.start()
        pass

    def register_me(self):
        while True:
            for i in range(1, 256):
                try:
                    self.regs.sendto(pickle.dumps(self.addr, pickle.HIGHEST_PROTOCOL),
                                     ("ukko%03i.hpc.cs.helsinki.fi" % i, self.addr[1]))
                except Exception, err:
                    print "Exception:centermc.py:MyListener.register_me():", err
            time.sleep(300)
        pass

    def listen_forever(self):
        self.server.serve_forever()
        pass

#
# This script provides some helper functions for all the classes in cluster
# subject. The helper functions included here should only be restricted within
# the scope of this sub-project.
#
# Liang Wang @ Dept. of Computer Science, University of Helsinki, Finland
# 2011.03.08
#

import re
import os,sys
import struct
import pickle
import urllib2
import subprocess

def are_rects_overlapped(rect1, rect2):
    """Check whether two rects are overlapped or not?"""
    overlapped = False
    x1, y1, w1, h1 = rect1
    x2, y2 = x1+w1, y1+h1
    x3, y3, w2, h2 = rect2
    x4, y4 = x3+w2, y3+h2
    if (x1<x3<x2 or x1<x4<x2 or x3<x1<x4 or x3<x2<x4) and (y1<y3<y2 or y1<y4<y2 or y3<y1<y4 or y3<y2<y4):
        overlapped = True
    return overlapped

def get_myip():
    return subprocess.Popen(["hostname","-I"], stdout=subprocess.PIPE).communicate()[0].split()[0]

def calc_rate(r):
    """Calculate the rate, and convert it into suitable measure unit. r should be in bytes."""
    s = ""
    if r < 2**10:
        s = "%i B/S" % r
    elif 2**10 <= r < 2**20:
        s = "%i KB/S" % int(r/2**10)
    elif 2**20 <= r < 2**30:
        s = "%i MB/S" % int(r/2**20)
    elif 2**30 <= r < 2**40:
        s = "%i GB/S" % int(r/2**30)
    elif 2**40 <= r < 2**50:
        s = "%i TB/S" % int(r/2**40)
    return s

def get_power_consumption():
    power = 0
    try:
        s = urllib2.urlopen("http://www.cs.helsinki.fi/u/jjaakkol/hpc-report.txt", timeout=5).read()
        for x in re.findall(r"(\d+)\W*?W", s, re.I):
            x = int(x)
            power += x
    except Exception, err:
        print "Exception:myutil.py:get_power_consumption():", err
    return power

def get_pc_mikko():
    power = None
    try:
        f = open("/group/home/greenict/public_html/exactum-kwhcalc/last-minute-watts.txt", "r")
        power = int(re.search(r".*?;.*?;(\d+)", f.readlines()[0]).group(1))
    except Exception, err:
        print "Exception:myutil.py:get_pc_mikko():", err
    return power

#
# This file is the main UI of cluster monitor.
#
# Liang Wang @ Dept. of Computer Science, University of Helsinki, Finland
# 2011.03.07
#

import re
import wx
import time
import random
import threading
import subprocess
import multiprocessing

class Node(object):
    def __init__(self, id=None, parent=None):
        self.id = id
        self.parent = parent
        self.name = "n%03i" % (id+1)
        self.highlight = False
        self.fontsize = 8
        self.x, self.y = 0, 0
        self.w, self.h = 100, 100
        self.plx, self.ply = 9, 9
        self.plw, self.plh = 9, 9
        self.pmx, self.pmy = 9, 9
        self.pmw, self.pmh = 9, 9
        self.r, self.rn = 3, 30.0        # Radius and Max num of histories
        self.rr_history = [1]
        self.tr_history = [1]
        # The states a node maintains
        self.ts = 0                      # Timestamp for the last message
        self.load = 0.0                  # 1 min average load
        self.cpu_count = 1.0             # Num of CPU cores
        self.mem_used = 0.0              # Used mem
        self.mem_total = 1.0             # Total physic mem
        self.user_count = 0              # Num of login users
        self.user_uniq = 0               # Num of uniq users
        self.disk = ""                   # Disk usage
        self.rx = ""                     # Total data recv by eth
        self.tx = ""                     # Total data send by eth
        self.rr = 0                      # The eth interface recv rate
        self.tr = 0                      # The eth interface send rate
        pass

    def draw(self, dc):
        self.draw_text_info(dc)
        self.draw_node_loadbar(dc, self.load/self.cpu_count, self.mem_used/self.mem_total)
        self.draw_speed_curve(dc)
        self.draw_frame(dc)
        self.parent.rr_total += self.rr
        self.parent.tr_total += self.tr
        pass

    def draw_frame(self, dc):
        x, y, w, h = self.x, self.y, self.w, self.h
        if self.highlight:
            dc.SetPen(wx.Pen('red', 2))
        else:
            dc.SetPen(wx.Pen(wx.Colour(64,64,64), 1))
        dc.SetBrush(wx.TRANSPARENT_BRUSH)
        dc.DrawRectangle(x, y, w, h)
        pass

    def draw_text_info(self, dc):
        x, y, w, h, fz = self.x, self.y, self.w, self.h, self.fz
        dc.SetFont(wx.Font(fz, wx.FONTFAMILY_SWISS,wx.FONTSTYLE_NORMAL,wx.FONTWEIGHT_NORMAL))
        if time.time() - self.ts < 60:
            dc.SetTextForeground('green')
        else:
            dc.SetTextForeground('grey')
        if w < 100:
            dc.DrawText("%s" % (self.name), x+1, y)
        else:
            dc.DrawText("%s D:%s U:%i" % (self.name, self.disk, self.user_count), x+2, y)
            dc.DrawText("R:%s T:%s" % (self.rx, self.tx), x+2, y+fz+3)
        pass

    def draw_node_loadbar(self, dc, load, mem):
        load = load if load <= 1 else 1.0
        mem  = mem  if mem  <= 1 else 1.0
        x, y, w, h = self.x, self.y, self.w, self.h
        plx, ply, plw, plh = self.plx, self.ply, self.plw, self.plh
        pmx, pmy, pmw, pmh = self.pmx, self.pmy, self.pmw, self.pmh
        dc.SetPen(wx.Pen('black', 0, wx.TRANSPARENT))
        dc.SetBrush(wx.BLACK_BRUSH)
        dc.GradientFillLinear((plx+1,ply+1,plw-2,plh-2), 'green', 'red')
        dc.GradientFillLinear((pmx+1,pmy+1,pmw-2,pmh-2), 'green', 'red')
        dc.DrawRectangle(plx+plw*load+1,ply+1,plw*(1-load)-1,plh-2)
        dc.DrawRectangle(pmx+pmw*mem+1,pmy+1,pmw*(1-mem)-1,pmh-2)
        pass

    def draw_speed_curve(self, dc):
        x, y, w, h, r = self.x, self.y, self.w, self.h, self.r
        rn = int(w/r)
        self.rr_history.append(self.rr)
        self.tr_history.append(self.tr)
        norm = max(max(self.rr_history), max(self.tr_history))
        self.parent.norm = max(norm, self.parent.norm)
        norm = 3.5*self.parent.norm
        self.rr_history = self.rr_history[-rn:]
        self.tr_history = self.tr_history[-rn:]
        dc.SetPen(wx.Pen("cyan", 0, wx.TRANSPARENT))
        dc.SetBrush(wx.GREEN_BRUSH)
        for i in range(1, len(self.rr_history)):
            rr = self.rr_history[-i]
            rh = int(h*rr/(norm))
            ry = y + h - rh
            rx = x + w - i*r
            rd = int(r/2)
            dc.DrawRectangle(rx-rd, ry, r-1, rh)
        dc.SetPen(wx.Pen("cyan", 0, wx.TRANSPARENT))
        dc.SetBrush(wx.RED_BRUSH)
        for i in range(1, len(self.tr_history)):
            tr = self.tr_history[-i]
            th = int(h*tr/(norm))
            ty = y + h - th
            tx = x + w - i*r
            dc.DrawRectangle(tx, ty, r-1, th)
        pass

class MyFrame(wx.Frame):
    def __init__(self, parent, title, size):
        self.matrix_x, self.matrix_y = 16, 15
        self.nodes = [ Node(i, self) for i in range(self.matrix_x*self.matrix_y) ]
        self.norm = 10
        self.nodes_lock = threading.Lock()
        self.rr_total = 0
        self.tr_total = 0
        self.power_consumption = get_pc_mikko()
        wx.Frame.__init__(self, parent, wx.ID_ANY, title, size=size)
        self.anchor0 = None
        self.anchor1 = None
        self.last_refresh = time.time()
        self.event = threading.Event()
        self.SetBackgroundColour('black')
        wx.EVT_SIZE(self, self.on_size)
        wx.EVT_PAINT(self, self.on_paint)
        wx.EVT_LEFT_DOWN(self, self.on_left_down)
        wx.EVT_LEFT_UP(self, self.on_left_up)
        wx.EVT_MOTION(self, self.on_motion)
        wx.EVT_RIGHT_DCLICK(self, self.btexp)
        wx.EVT_CLOSE(self, self.on_close)
        # Start the timer to refresh the frame periodically
        self.timer = wx.Timer(self, id=-1)
        self.Bind(wx.EVT_TIMER, self.update, self.timer)
        self.timer.Start(1000)
        # Start the timer to refresh power consumption periodically
        self.power_consumption_timer = wx.Timer(self, id=-1)
        self.Bind(wx.EVT_TIMER, self.update_power_consumption, self.power_consumption_timer)
        self.power_consumption_timer.Start(5*1000)

        pass

    def Show(self):
        wx.Frame.Show(self)
        self.on_size()

    def on_size(self, event=None):
        mx, my = self.matrix_x, self.matrix_y
        scrW, scrH = wx.PaintDC(self).GetSize()
        nw, nh = scrW/mx - 2, scrH/my - 2
        fz = 7 if int(min(nw,nh)/9.5)<7 else int(min(nw,nh)/9.5)
        r, rn = self.nodes[0].r, self.nodes[0].rn
        r = 3 if int(r/rn)<3 else int(r/rn)
        for i in range(my):
            for j in range(mx):
                id = i*mx+j
                node = self.nodes[id]
                node.w, node.h = nw, nh
                node.x, node.y = (nw+2)*j+2, (nh+2)*i+2
                node.plx = node.x + 0.02*nw
                node.ply = node.y + 0.35*nh
                node.plw = nw*0.95
                node.plh = nh*0.15
                node.pmx = node.plx
                node.pmy = node.ply + node.plh + 0.04*nh
                node.pmw = node.plw
                node.pmh = node.plh
                node.fz  = fz
                node.r   = r
        self.Refresh(False)
        pass

    def on_paint(self, event=None):
        dc = wx.PaintDC(self)
        dc.SetPen(wx.Pen('black', 0))
        self.nodes_lock.acquire()
        try:
            self.draw_nodes(dc)
        except Exception, err:
            print "Exception:MyFrame.on_paint():", err
        self.nodes_lock.release()
        self.draw_select_rect(dc)
        self.set_frame_title()
        self.last_refresh = time.time()
        pass

    def update(self, event=None):
        self.norm = 10 if self.norm*0.95<10 else self.norm*0.95
        self.rr_total, self.tr_total = 0, 0
        self.Refresh(False)

    def update_power_consumption(self, event=None):
        self.power_consumption = get_pc_mikko()
        pass

    def btexp(self, event=None):
        args = []
        for node in self.nodes:
            if node.highlight:
                args += [str(node.id+1)]
        subprocess.Popen(["./btexp.py"] + args)
        pass

    def draw_nodes(self, dc):
        for node in self.nodes:
            node.draw(dc)
        pass

    def on_left_down(self, event=None):
        self.anchor0 = (event.m_x, event.m_y)
        pass

    def on_left_up(self, event=None):
        self.highlight_nodes()
        self.anchor0 = None
        self.Refresh(False)
        pass

    def on_motion(self, event=None):
        self.anchor1 = (event.m_x, event.m_y)
        if self.anchor0:
            self.Refresh(False)
        pass

    def on_close(self, event=None):
        self.event.set()
        event.Skip()
        pass

    def draw_select_rect(self, dc):
        if self.anchor0:
            x1, y1 = self.anchor0
            x2, y2 = self.anchor1
            x,  y  = min(x1,x2), min(y1,y2)
            w,  h  = abs(x1-x2), abs(y1-y2)
            dc.SetPen(wx.Pen('red', 3, wx.SHORT_DASH))
            dc.SetBrush(wx.TRANSPARENT_BRUSH)
            dc.DrawRectangle(x, y, w, h)
        pass

    def highlight_nodes(self):
        if self.anchor0 and self.anchor1:
            x1,y1,x2,y2 = self.anchor0[0],self.anchor0[1],self.anchor1[0],self.anchor1[1]
            rect = (min(x1,x2),min(y1,y2),abs(x1-x2),abs(y1-y2))
            for node in self.nodes:
                if are_rects_overlapped(rect, (node.x,node.y,node.w,node.h)):
                    node.highlight = not node.highlight
        pass

    def set_frame_title(self):
        rr = calc_rate(self.rr_total)
        tr = calc_rate(self.tr_total)
        self.SetTitle("UKKO CLUSTER  PC: %s W  RX: %s  TX: %s" % (str(self.power_consumption), rr, tr))
        pass

    def process_multicast(self):
        while not self.event.isSet():
            try:
                data = INCQUE.get()
                self.nodes_lock.acquire()
                id = int(re.search(r"(\d+)", data["nodename"]).group(1)) - 1
                n = self.nodes[id]
                n.ts = time.time()
                n.load = float(data["load"])
                n.cpu_count = float(data["cpu_count"])
                n.mem_used = float(data["mem_used"])
                n.mem_total = float(data["mem_total"])
                n.user_count = int(data["user_count"])
                #n.user_uniq = int(data["user_uniq"])
                n.disk = data["disk"]
                n.rx = data["rx"]
                n.tx = data["tx"]
                n.rr = data["rr"]
                n.tr = data["tr"]
                self.nodes_lock.release()
            except Exception, err:
                self.nodes_lock.release()
                print "Exception:process_multicast():", err
    pass

if __name__=="__main__":
    app = wx.App()
    frame = MyFrame(None, "UKKO Cluster", (800,600))
    frame.Show()
    # Start the multicast listener as daemon
    listener = Process(target=MyListener(None, 1212, True).listen_forever, args=())
    listener.daemon = True
    listener.start()
    # Start the worker thread for processing update multicasts
    t = threading.Thread(target=frame.process_multicast, args=())
    t.daemon = True
    t.start()
    # Start the app's mainloop
    app.MainLoop()
