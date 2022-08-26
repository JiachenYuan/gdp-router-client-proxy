import logging
from flask import Flask
from scapy.all import *
import socket
from datetime import datetime
import hashlib
import protobuf.GdpMsg_pb2



GdpName = None
app = Flask(__name__)
import routes

class GDP(Packet):
    name = "Gdp_Header"
    fields_desc = [
        ByteField("action", 1),
        ShortField("data_len", 0),
        BitField("src_gdpname", 0, 256),
        BitField("dst_gdpname", 0, 256)
    ]


def send_register_packet(local_ip, switch_ip, GdpName):
    packet = Ether(dst = 'ff:ff:ff:ff:ff:ff') / \
                IP(src=local_ip, dst=switch_ip)/ \
                    UDP(sport=31415, dport=31415)/ \
                        GDP(data_len=32, src_gdpname=GdpName, action=1)/ \
                            socket.inet_aton(local_ip)

    # print(socket.inet_ntoa(packet[GDP].payload.load))

    sendp(packet)
    
    return






def register_proxy(switch_ip):
    print("Sending initial binding registration")
    # todo: register it self by constructing and sending a Gdp message to the switch it binds 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
    print("I am a client-side proxy of GDP switch, my IP = {}".format(local_ip_address))

    curr_time = datetime.now()
    string_to_hash = str(curr_time) + str(app.config['switch_ip'])
    GdpName = hashlib.sha256(string_to_hash.encode('utf-8'))
    # We need human-readable hex string for GdpName instead of bytes 
    to_return = GdpName.hexdigest()
    GdpName_in_byte = GdpName.digest()

    GdpName_in_byte = int.from_bytes(GdpName_in_byte, "big")

    print("My GdpName in 64 hex string is = {}".format(to_return))

    send_register_packet(local_ip_address, switch_ip, GdpName_in_byte)

    return to_return


def create_app(switch_ip):

    app.logger.setLevel(logging.INFO)
    app.config['switch_ip'] = switch_ip

    print("Passed in switch ip = " + app.config['switch_ip'])

    GdpName = register_proxy(switch_ip)
    app.config['GdpName'] = GdpName
    return app



if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-t')
    args = parser.parse_args()
    switch_ip = args.t

    app = create_app(switch_ip)

    app.run(debug=False)






