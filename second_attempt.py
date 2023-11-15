import argparse
import socket
import threading
from scapy.all import *

def handle_client(client_sock, target_host, target_port):
    try:
        # print(f"checking parameters: {client_sock}, {target_host}, {target_port}")
        # get response from client
        client_response = client_sock.recv(4096)
        print(f"client response: {client_response}")
        # forward response from client to target server
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.connect((target_host, target_port))
        target_sock.sendall(client_response)
        # get response from server
        server_response = target_sock.recv(4096)
        # forwars server response to client
        client_sock.sendall(server_response)
    except KeyboardInterrupt:
        # Close the sockets??
        client_sock.close()
        target_sock.close()
        exit(0)

def start_proxy(bind_ip, bind_port, target_host, target_port):
    # Create a socket to listen for incoming connections i.e., pretend to be a server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((bind_ip, bind_port))
    server_sock.listen(5)
    print(f"Listening on {bind_ip}:{bind_port}")

    while True:
        try:
            client_sock, addr = server_sock.accept()
            print(f"Accepted connection from: {addr[0]}:{addr[1]}")
            # Create a thread to handle the connection
            client_thread = threading.Thread(target=handle_client, args=(client_sock, target_host, target_port))
            client_thread.start()
        except KeyboardInterrupt:
            server_sock.close()
            client_sock.close()
            exit(0)

def passive_mode(pkt):
    # TODO: implement
    # print("am i here? + pkt deets:", pkt)
    # if pkt.haslayer(TCP) and pkt.haslayer(Raw):
    #     # Check if the packet contains HTTP GET or POST traffic
    #     if b"GET " in pkt[Raw].load or b"POST " in pkt[Raw].load:
    #         print("HTTP GET or POST Packet found:")
    #         print(pkt.show())
    pass

def active_mode(pkt):
    # TODO: implement
    pass

if __name__ == "__main__":
    # handling args
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', default="passive", dest="mode")
    parser.add_argument("listening_ip")
    parser.add_argument("listening_port")
    args = parser.parse_args()

    # setting up basic proxy
    target_host = "example.com"
    target_port = 80

    # print(args)
    if args.mode == "passive":
        start_proxy(args.listening_ip, int(args.listening_port), target_host, target_port)
    elif args.mode == "active":
        # bpf_filter = f"host {args.listening_ip} and tcp port {args.listening_port}" 
        # sniff(filter=bpf_filter, prn=active_mode, store=False)
        active_mode(args.listening_ip, args.listening_port)
    else:
        print("illegal mode: choose between [active/passive]")
        exit(0)


