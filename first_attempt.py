import argparse
from scapy.all import *

def passive_mode(pkt):
    # TODO: implement
    print("am i here? + pkt deets:", pkt)
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        # Check if the packet contains HTTP GET or POST traffic
        if b"GET " in pkt[Raw].load or b"POST " in pkt[Raw].load:
            print("HTTP GET or POST Packet found:")
            print(pkt.show())

def active_mode(pkt):
    # TODO: implement
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', default="passive", dest="mode")
    parser.add_argument("listening_ip")
    parser.add_argument("listening_port")
    args = parser.parse_args()
    # print(args)
    if args.mode == "passive":
        bpf_filter = f"host {args.listening_ip} and tcp port {args.listening_port}" 
        print("bpf_filter:", bpf_filter)
        sniff(filter=bpf_filter, iface=scapy.interfaces.get_working_if(), prn=passive_mode, store=False, count=5)
        # sniff(iface=scapy.interfaces.get_working_if(), prn=passive_mode, store=False)
        # passive_mode(args.listening_ip, args.listening_port)
    elif args.mode == "active":
        bpf_filter = f"host {args.listening_ip} and tcp port {args.listening_port}" 
        sniff(filter=bpf_filter, prn=active_mode, store=False)
        # active_mode(args.listening_ip, args.listening_port)
    else:
        print("illegal mode: choose between [active/passive]")
        exit(0)


