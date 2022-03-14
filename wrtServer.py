#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import time
import os
from datetime import datetime
from multiprocessing import Process, Queue, Lock

HOST = '0.0.0.0'
PORT = 7777

ServerIP = '192.168.1.4'
ServerPort = 8888

MAXCONN = 2

def server( ip, port, ACCUSERS,ACCCTRLS,CLIMSG ):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    print('server start at: %s:%s' % (ip, port))
    print('wait for connection...')
    while True:
        conn, addr = s.accept()
        print('connected by ' + str(addr))
        while True:
            indata = conn.recv(1024)
            if len(indata) == 0: # connection closed
                conn.close()
                print('client closed connection.')
                break
            print( indata.decode() )
            conn.send( CLIMSG.get().encode() )

def accessControl( ACCUSERS,ACCCTRLS,mutex ):
    rule = []
    while True:
        rule.append( ACCCTRLS.get() )
        if( len(rule) >= 5 ):
            mutex.acquire()
            print( "write accessControl rule" )

            f = open("/etc/firewall.user", "r")
            lines = f.readlines()
            f.close()

            macAcc = {}
            for r in rule:
                mac0 = r.split(",")[1] #mac:ac:e3:42:24:19:da
                mac1 = mac0.split(":")
                mac = mac1[1]+":"+mac1[2]+":"+mac1[3]+":"+mac1[4]+":"+mac1[5]+":"+mac1[6]
                acc = r.split(",")[3].split(":")[1][0] #1}
                macAcc[mac] = acc
            print(macAcc)

            f = open("/etc/firewall.user", "w")

            mac = ""
            numConn = 0
            for line in lines:
                if not line.isspace():
                    spt = line.strip("\n").split(" ");
                    if len(spt) > 8:
                        mac = line.strip("\n").split(" ")[8]
                    else: mac = ""
                    if mac in macAcc:
                        acc0 = ""
                        if( macAcc[mac] == "1" ):
                            acc0 = "ACCEPT"
                            numConn += 1
                        else: acc0 = "REJECT"
                        if numConn <= MAXCONN:
                            f.write("iptables -I FORWARD -p all -m mac --mac-source " + mac + " -j " + acc0 + "\n")
                        else:
                            f.write("iptables -I FORWARD -p all -m mac --mac-source " + mac + " -j " + "REJECT" + "\n")
                            CLIMSG.put("exceed max connection")
                        del macAcc[mac]
                    else:
                        f.write(line)

            for mac in macAcc:
                acc0 = ""
                if( macAcc[mac] == "1" ):
                    acc0 = "ACCEPT"
                    numConn += 1
                else: acc0 = "REJECT"
                if numConn <= MAXCONN:
                    f.write("iptables -I FORWARD -p all -m mac --mac-source " + mac + " -j " + acc0 + "\n")
                else:
                    f.write("iptables -I FORWARD -p all -m mac --mac-source " + mac + " -j " + "REJECT" + "\n")
                    CLIMSG.put("exceed max connection")

            f.close()
            rule = []
            os.system("/etc/init.d/firewall restart")
            mutex.release()

def queryServer( ACCUSERS,ACCCTRLS ):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ServerIP, ServerPort))
            while True:
                s.send(ACCUSERS.get().encode())
                indata = s.recv(1024)
                if len(indata) == 0: # connection closed
                    s.close()
                    print('server closed connection.')
                    break
                ACCCTRLS.put( indata.decode() )
                time.sleep(10)
        except:
            print("try reconnect server...")
            time.sleep(10)
        else:
            print("connected to server")

def getClient( ACCUSERS,ACCCTRLS ):
    while True:
        with open('/tmp/dhcp.leases', encoding='utf8') as f:
            for line in f:
                sline = line.strip()
                #print(sline)
                info = sline.split(" ")
                #print(info)
                now = datetime.now()
                dt = now.strftime("%Y-%m-%dT%H:%M:%S")
                ACCUSERS.put( "{user:" + info[3] + "," + "mac:" + info[1] + "," + "time:" + dt + ",access:?,router:redmiAC2201}" )
        time.sleep(10)

if __name__ == '__main__':
    ACCUSERS = Queue()
    ACCCTRLS = Queue()
    CLIMSG = Queue()
    mutex = Lock()
    
    getClient_process = Process(target = getClient, args=(ACCUSERS,ACCCTRLS))
    accessControl_process = Process(target = accessControl, args=(ACCUSERS,ACCCTRLS,mutex))
    queryServer_process = Process(target = queryServer, args=(ACCUSERS,ACCCTRLS))

    getClient_process.start()
    accessControl_process.start()
    queryServer_process.start()

    server_process = Process(target = server, args = (HOST,PORT,ACCUSERS,ACCCTRLS,CLIMSG))
    server_process.start()