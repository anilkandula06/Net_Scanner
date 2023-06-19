#!/usr/bin env python
import scapy.all as scapy

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_brod = broadcast/arp_req
    #print(arp_req_brod.summary())
    answered_list = scapy.srp(arp_req_brod, timeout=3, verbose=False)[0]

    client_list = []
    for host_data in answered_list:
      client_dict = {"ip":host_data[1].psrc, "mac":host_data[1].hwsrc}  #(packetsent,answer) which is host_data[1] = ans
      client_list.append(client_dict)   #add client to the list
      #print(host_data[1].psrc + "\t\t" + host_data[1].hwsrc)
    return client_list


def print_result(host_result):
    print("-----------------------------------------")
    print("IP\t\t\tAt MAC Address A\n-----------------------------------------")
    for client in host_result:
        print(client["ip"] + "\t\t" + client["mac"])

enterIp = input("Enter the target Ip> ")
scan_result = scan(enterIp)
print_result(scan_result)
