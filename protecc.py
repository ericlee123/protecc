import argparse
import logging
import netifaces
import os
import socket
import subprocess
import sys
import threading
import time

# Import smtplib for the actual sending function
import smtplib
import os
import sys
# Import the email modules we'll need
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# to suppress IPv6 warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class Protecc:
    def __init__(self, internet, monitor, sniffTime, whitelist, outputFolder):
        self.internet = internet
        self.monitor = monitor
        self.sniffTime = sniffTime
        # MAC -> port -> freq
        self.incomingMACs = {}
        self.blacklist = set()

        # load whitelist
        self.whitelist = []
        if whitelist is not None:
            wl = open(whitelist, "r")
            self.whitelist = wl.read().splitlines()

        # make output folder if necessary
        os.makedirs(outputFolder, exist_ok=True)
        if outputFolder[-1:] == '/':
            self.outputFolder = outputFolder[:-1]
        else:
            self.outputFolder = outputFolder

    def receivePacket(self, pkt):
        selfIP = self.getInterfaceIP(self.internet)

        if IP in pkt:
            # TODO: detect attacks not necessarily directed at my computer
            if pkt[IP].dst == selfIP:
                srcIP = pkt[IP].src
                srcMAC = pkt[Ether].src

                # TODO: also track UDP
                if TCP in pkt:
                    srcPort = pkt[TCP].sport
                    dstPort = pkt[TCP].dport
                else:
                    return

                if srcMAC not in self.blacklist and srcMAC not in self.whitelist:

                    # count it
                    if srcMAC not in self.incomingMACs:
                        self.incomingMACs[srcMAC] = {}
                        self.incomingMACs[srcMAC][dstPort] = 1
                    else:
                        if dstPort not in self.incomingMACs[srcMAC]:
                            self.incomingMACs[srcMAC][dstPort] = 0
                        self.incomingMACs[srcMAC][dstPort] += 1

                    firstDotIndex = selfIP.index(".")
                    secondDotIndex = selfIP.index(".", firstDotIndex + 1)
                    subnetCheck = selfIP[:secondDotIndex]
                    local = srcIP.startswith(subnetCheck)

                    if len(self.incomingMACs[srcMAC]) > 100: # maybe nmap
                        print("===========================================")
                        if local: # true if traffic is from local network
                            print("potential nmap scan over the local network from " + srcIP + " (" + srcMAC + ")")
                            print("doing the protecc...")
                            self.defend(srcMAC, srcIP)
                        else:
                            print("potential nmap scan over the internet from " + srcIP + " (" + srcMAC + ")")
                            location = subprocess.check_output(["geoiplookup", srcIP]).decode('utf-8')
                            print("traffic coming from " + location)
                            self.blockIP(srcIP)
                        self.blacklist.add(srcMAC)

                    elif self.incomingMACs[srcMAC][dstPort] > 100: # maybe brute force
                        print("===========================================")
                        if local:
                            print("potential brute force attack detected over the local network from " + srcIP + " (" + srcMAC + ")")
                            print("doing the protecc...")
                            self.defend(srcMAC, srcIP)
                        else:
                            print("potential brute force attack detected over the internet from " + srcIP + " (" + srcMAC + ")")
                            location = subprocess.check_output(["geoiplookup", srcIP]).decode('utf-8')
                            print("traffic coming from " + location)
                            self.blockIP(srcIP)
                        self.blacklist.add(srcMAC)

    def defend(self, attackerMAC, attackerIP):
        self.setMonitorMode()
        routerMAC = self.findRouterMAC()
        self.logNmap(attackerIP)
        thread = threading.Thread(target=self.spamDeauthPackets, args=[32, routerMAC, attackerMAC, self.monitor])
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
            subprocess.run(["aireplay-ng", "-0", str(count), "-a", routerMAC, "-c", attackerMAC, interface], stdout=subprocess.PIPE)
            time.sleep(5)

    def logNmap(self, ip):
        subprocess.run(["nmap", "-A", "-oN", self.outputFolder + "/nmap-" + ip + ".log", ip], stdout=subprocess.PIPE)

    def sniffProbeRequests(self, macAddress, sniffTime):
        subprocess.run("timeout " + str(sniffTime) + "s " \
                       "python probemon.py -i " + self.monitor + " -o " + self.outputFolder + "/sneaks-" + macAddress + ".log -t unix -fsrl | " \
                       "grep --line-buffered " + macAddress + " > " + self.outputFolder + "/filteredSneaks-" + macAddress + ".log", shell=True)
        print("probe sniffing on " + macAddress + " completed")

    def blockIP(self, ip):
        ret = subprocess.check_output(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]).decode('utf-8')
        if ret == "":
            print("blocked external IP (" + ip + ") with iptables")

    def sendEmail(self, type, warning):
        email = ""
        wordpass = ""

        # login to gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email, wordpass)

        msg = 'Subject: {}\n\n{}'.format("ALERT: {}".format(type), warning)

        # for now, sending email to myself
        server.sendmail(email, email, msg)
        server.quit()

DESCRIPTION = "Automated counter attack service for public wifi"

def doSniff(interface, protecc):
    sniff(iface=interface, prn=protecc.receivePacket)

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-i", "--internet-interface", type=str, help="internet interface")
    parser.add_argument("-m", "--monitoring-interface", type=str, help="sniff + deauth interface")
    parser.add_argument("-o", "--output-folder", default="out", help="folder for output files")
    parser.add_argument("-s", "--sniff-time", default=60, help="how long, in seconds, to sniff for probe requests")
    parser.add_argument("-w", "--whitelist", help="MAC address whitelist (newline separated)")
    args = parser.parse_args()

    if not args.internet_interface:
        print("ERROR: pls provide internet interface")
        sys.exit(-1)

    if not args.monitoring_interface:
        print("ERROR: pls provide monitor supported interface")
        sys.exit(-1)

    p = Protecc(args.internet_interface, args.monitoring_interface, args.sniff_time, args.whitelist, args.output_folder)

    thread = threading.Thread(target=doSniff, args=[args.internet_interface, p])
    thread.start()


if __name__ == "__main__":
    main()
