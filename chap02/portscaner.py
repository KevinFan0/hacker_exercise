#TCP全连接扫描

import optparse
from socket import *
from threading import Thread, Semaphore


#利用线程去扫描
screenLock = Semaphore(value=1) #屏幕控制权的锁  semaphore为信号量
def connScan(tgtHost,tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('ViolentPython\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print("[+]%d/tcp open" % tgtPort)
        print("[+] " + str(results))
        connSkt.close()
    except:
        screenLock.acquire()
        print("[-]%d/tcp closed" % tgtPort)
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost,tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-]")
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print("\n[+] Scan Result for : " + tgtName[0])
    except:
        print("\n[+] Scan Result for : " + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        # print("Scanning port " + tgtPort)
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()


def main():
    parser = optparse.OptionParser("usage %prog -H" + "<target host> -p <target port>")
    parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
    parser.add_option("-p", dest="tgtPort", type="string", help="specify target(s) port")
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print(parser.usage)
        exit(0)

    portScan(tgtHost,tgtPorts)

if __name__ == "__main__":
    main()

