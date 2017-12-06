# protecc
CS378 Ethical Hacking Project
Maurya Avirneni, Eric Lee, Alex Ng, Robert Monetfusco

## Synopsis 
Protecc is a threat detection tool that monitors incoming packets to a host and counters suspicious behavior. Specifically, protecc can detect nmap scans and dictionary attacks from both public IPs and (potentially) infected local machines. Once a threat is detected, protecc extracts various details from the attacker, including IP address, MAC address, OS information, etc., and then sends a detailed alert to the system admin. It can then send  deauth packets to the attacking host via MAC address on the local network and the host will be disconnected from the network. Each part of the project has the ability to run independently from the main tool functionality, so more features can be easily implemented or removed depending on the specific user’s needs.


## Outline
1. Detect suspicious behavior
	- Use packet analysis tool to monitor for nmap scans and dictionary attacks
	- Save attacker IP address
2. Information retrieval
	- Run nmap on attacker's IP and save the results
	- If public IP, run geoip-lookup to find location and ISP information
3. Counter
	- Retrieve router mac address
	- Send deauth packets to attacker
	- Gather information on the resulting probe requests (harvest SSIDs)

## Prerequisites
- [netaddr](https://github.com/drkjam/netaddr)
- [scapy](https://github.com/secdev/scapy)
- [geoip](https://packages.debian.org/wheezy/geoip-bin)
