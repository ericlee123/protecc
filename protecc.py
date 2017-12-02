import argparse
import sys

class Protecc:

    def __init__(self, interface, whitelist):
        self.interface = None

    def defend(self):
        print "defend"

DESCRIPTION = "Automated counter attack service for public wifi"

def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("-i", "--interface", help="sniff + deauth interface")
    parser.add_argument("-o", "--output", help="result output location")
    parser.add_argument("-w", "--whitelist", help="MAC address whitelist (newline separated)")
    args = parser.parse_args()

    if not args.interface:
        print "ERROR: pls provide monitor supported interface"
        sys.exit(-1)

    p = Protecc(args.interface, args.whitelist)
    p.defend()

if __name__ == "__main__":
    main()
