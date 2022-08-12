import logging
from flask import Flask
from scapy.all import *
import socket
from datetime import datetime
import hashlib




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


def prepare_register_packet(local_ip, switch_ip):
    curr_time = datetime.now()
    string_to_hash = str(curr_time) + str(local_ip)
    GdpName = hashlib.sha256(string_to_hash.encode('utf-8')).digest()
    GdpName = int.from_bytes(GdpName, "little")
    print(GdpName)



    packet = Ether(dst = 'ff:ff:ff:ff:ff:ff') / \
                IP(src=local_ip, dst=switch_ip)/ \
                    UDP(sport=31415, dport=31415)/ \
                        GDP(data_len=32, src_gdpname=GdpName)/ \
                            socket.inet_aton(local_ip)

    # print(socket.inet_ntoa(packet[GDP].payload.load))

    sendp(packet)
    
    return






def register_proxy(switch_ip):
    app.logger.info("Sending initial binding registration")
    # todo: register it self by constructing and sending a Gdp message to the switch it binds 
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
    app.logger.info("I am a client-side proxy of GDP switch, my IP = " + local_ip_address)

    prepare_register_packet(local_ip_address, switch_ip)

    return


def create_app(switch_ip):

    app.logger.setLevel(logging.INFO)
    app.config['switch_ip'] = switch_ip

    app.logger.info("Passed in switch ip = " + app.config['switch_ip'])

    register_proxy(switch_ip)
    
    return app



if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-t')
    args = parser.parse_args()
    switch_ip = args.t

    app = create_app(switch_ip)

    app.run(debug=True)






