from socket import error as sock_err
import socket

import tkinter as tk
import tkinter.scrolledtext as tkst

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

import threading


myip = ""
count = 1
detectedIPs = dict()
warnList = dict()
sshList = dict()

win = tk.Tk()
win.minsize(450, 250)
frame1 = tk.Frame(master = win, bg = '#808000')
frame1.pack(fill='both', expand='yes')

editArea = tkst.ScrolledText(master = frame1, wrap = tk.WORD, width = 90, height = 40)
editArea.pack(padx=0, pady=0, fill=tk.BOTH, expand=True)
editArea.insert(tk.INSERT, "")
editArea.configure(state = "disabled")

def doSniff():
    sniff(iface="wlan0", prn=printTest)

def printTest(pkt):

    global myip
    global count
    global detectedIPs

    if TCP in pkt:

        if myip == "" and count == 1:
            myip = pkt[IP].dst
        if myip == "" or myip == "127.0.0.1":
            print("\n--- A network error occurred making the network or host unreachable.")
            exit()

        print("my ip is " + myip)
        #print(pkt.summary())
        #print("\nsrc ip: " + pkt[IP].src + " port: " + str(pkt[TCP].sport))
        #print("dst ip: " + pkt[IP].dst + " port: " + str(pkt[TCP].dport))
        #print()

        firstDotIndex = pkt[IP].src.index(".")
        secondDotIndex = pkt[IP].src.index(".", firstDotIndex+1)

        if pkt[IP].dst == myip:
        #if True:
            output = "Packet #" + str(count) + " source ip is " + pkt[IP].src + " going to port " + str(pkt[TCP].dport)
            #print(output)
            count += 1

            try:
                detectCopy = detectedIPs[pkt[IP].src]

            except KeyError as keyError:
                print("making the detected list")
                detectedIPs[pkt[IP].src] = set()
                detectCopy = detectedIPs[pkt[IP].src]


            try:
                warn = warnList[pkt[IP].src]

            except KeyError as keyError:
                print("adding to warn list")
                warnList[pkt[IP].src] = False


            if pkt[TCP].dport == 22:
                try:
                    val = sshList[pkt[IP].src]

                except KeyError as keyError:
                    print("adding to ssh list")
                    sshList[pkt[IP].src] = 0

                val = sshList[pkt[IP].src]
                val += 1
                sshList[pkt[IP].src] = val
                if val > 100:
                    print("SSH BRUTEFORCE DETECTED from  " + pkt[Ether].src)

            detectCopy.add(pkt[TCP].dport)
            detectedIPs[pkt[IP].src] = detectCopy

            #print(detectedIPs[pkt[IP].src])
            warn = warnList[pkt[IP].src]
            if len(detectedIPs[pkt[IP].src]) > 100 and warn == False:
                print("\nNMAP SCAN DETECTED from " + pkt[Ether].src)
                warnList[pkt[IP].src] = True

            editArea.configure(state = "normal")
            editArea.insert(tk.INSERT, output + "\n")
            editArea.yview(tk.END)
            editArea.configure(state = "disabled")



def main():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        myip = s.getsockname()[0]

    except socket.error as socketError:
        if socketError.errno == socket.errno.ENETUNREACH:
            print("\n--- A network error occurred making the network or host unreachable.")
            print("--- " + str(socketError))
            exit()
        else:
            raise socketError

    s.close()

    thread = threading.Thread(target=doSniff, args=())
    thread.daemon = True
    thread.start()
    win.mainloop()
    #sniff(iface="wlan0", prn=printTest)



if __name__ == '__main__':
    main()
