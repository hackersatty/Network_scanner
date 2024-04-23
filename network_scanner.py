import scapy.all as scapy
import optparse

# optparse works in both python2 python3
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target /Ip range")
    (options, arguments)=parser.parse_args()
    return options
    
def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #[0] for only answered #to send a arp request use srp

    # print("IP\t\t\tMAC-ADDRESS\n-----------------------------------------")
    client_list =[]
    for elements in answered_list:
        client_dict={"ip":elements[1].psrc,"mac":elements[1].hwsrc}
        client_list.append(client_dict)
        # print(elements[1].psrc + "\t\t" + elements[1].hwsrc)
    return client_list
def print_result(result_list):
    print("IP\t\t\tMAC-ADDRESS\n-----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])
options = get_arguments()
scan_result=scan(options.target)
print_result(scan_result)
