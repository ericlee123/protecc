# protecc
CS378 Ethical Hacking Project

## Steps
1. detect suspicious behavior
	- use packet analysis tool to see if any requirements suspicious behavior is satisfied
	- save attacker's IP and MAC address for following steps
2. information retrieval
	- run nmap on attacker's IP and save the results
	- send deauth packets and gather information on the resulting probe requests
	- ??? more ???
3. counter
	- spam deauth packets as DDoS attack

## Prerequisites
- (netaddr)[https://github.com/drkjam/netaddr]
- (scapy)[https://github.com/secdev/scapy]
