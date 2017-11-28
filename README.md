# protecc
CS378 Ethical Hacking Project

1. identify an attacker (nmap, john, hydra, metasploit) 
	- use tcpdump in order to see if a single IP is targeting a large number of ports for nmap
	- figure out how to recognize large number ot packets sent to a single port (hydra attack prevention)
	- record their IP and MAC addresses (or whatever available info)
2. send them deauth packets
3. wait for them to reconnect
4. harvest their known connections
5. spam deauths after all information is obtained
