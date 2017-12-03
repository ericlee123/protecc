import argparse
import subprocess
import sys

class Protecc:
    def __init__(self, interface, whitelist):
        self.interface = interface

    def defend(self):
        macAddress = "ac:37:43:a3:fd:6f"
        ip = "192.168.1.7"
        sniffTime = 60
        self.setMonitorMode(self.interface)
        self.nmap(ip)
        self.sniffProbeRequests(macAddress, sniffTime)

    def setMonitorMode(self, interface):
        subprocess.run(["ifconfig", interface, "down"])
        subprocess.run(["iwconfig", interface, "mode", "monitor"])
        subprocess.run(["ifconfig", interface, "up"])

    def nmap(self, ip):
        subprocess.run(["nmap", "-A", "-oN", "nmap-"+ip+".log", ip])

    def sniffProbeRequests(self, macAddress, sniffTime):
        subprocess.run("timeout " + str(sniffTime) + "s " \
                       "python probemon.py -i " + self.interface + " -o sneaks.log -t unix -fsrl | " \
                       "grep --line-buffered " + macAddress + " > probeRequests.log", shell=True)

DESCRIPTION = "Automated counter attack service for public wifi"

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-i", "--interface", help="sniff + deauth interface")
    parser.add_argument("-o", "--output", help="result output location")
    parser.add_argument("-w", "--whitelist", help="MAC address whitelist (newline separated)")
    args = parser.parse_args()

    if not args.interface:
        print("ERROR: pls provide monitor supported interface")
        sys.exit(-1)

    p = Protecc(args.interface, args.whitelist)
    p.defend()

if __name__ == "__main__":
    main()
