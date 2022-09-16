# Address Resolution Protocol
import scapy.all as scapy #which allows to create, modify, send and capture network packets

def get_mac(ip):
    arp_req_frame = scapy.ARP(pdst = ip) # takes target host IP address as parameter and will return mac address of this host
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") #destination
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame #Scan network for live hosts 
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0] # for sending packets and receiving answers. 
    #The function returns a couple of packet and answers, and the unanswered packets

    return answered_list[0][1].hwsrc # This function takes target host IP address as parameter and will return mac address of this host.


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #Packet sniffer that will retrieve the URLS and any potential login information

def process_sniffed_packet(packet): #    # if the packet is an ARP packet

    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2: #  if it is an ARP response (ARP reply)

        try:
            real_mac=get_mac(packet[scapy.ARP].psrc)                 # get the real MAC address of the sender

            response_mac=packet[scapy.ARP].hwsrc                 # if they're different, definitely there is an attack


            if real_mac != response_mac:
                print("[+] You Are Under Attack!!!")
        except IndexError:
          # unable to find the real mac
                # may be a fake IP or firewall is blocking packets
            pass
#function to discard sniffed packets instead of storing them in memory, this is useful when the script runs for a very long time.
sniff("eth0")
