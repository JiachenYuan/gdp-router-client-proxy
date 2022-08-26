import hashlib
import multiprocessing
from struct import pack
from uuid import uuid4
from scapy.all import *
import socket
import threading

import protobuf.GdpMsg_pb2 as GdpMsg
from utils import get_local_ip

class GDP(Packet):
    name = "GDP"
    fields_desc = [
        ByteField("action", 1), # 1
        ShortField("data_len", 0), # 2
        BitField("src_gdpname", 0, 256), # 32
        BitField("dst_gdpname", 0, 256), # 32
        BitField("uuid", 0, 128), # 16
        IntField("num_packets", 1), # 4
        IntField("packet_no", 1), # 4
        
        
    ]

bind_layers(UDP, GDP, dport=31415)






class PacketSniffer:
    
    def __init__(self, switch_ip, uuid, num_packets) -> None:
        self.packet_pool = []
        self.switch_ip = switch_ip
        self.uuid = uuid
        self.packet_no_set = [0]*num_packets # 0 at ith position means packet packet number i+1 has not been received yet
    
    # bpf stands for Berkeley Packet Filter syntax
    # prn is a function that will be executed on each sniffed packet
    # stop_filter is a function that gives a boolean for whether to stop the sniffing. This function is applied to each packet
    # todo: change method name to avoid confusion with scapy.all.sniff
    def start_sniff(self, prn, stop_filter):
        # sniff(filter="src host {} and port 31415".format(self.switch_ip),  prn=prn, stop_filter=stop_filter)
        #! todo: solve duplicate packet problem
        sniff(prn=prn, stop_filter=stop_filter)
        print("Sniff stopped. Currently, packet_pool is of size = {}".format(len(self.packet_pool)))

    def get_packet_pool(self):
        return self.packet_pool
    
    def get_received_no_list(self):
        return self.packet_no_set
    
    def get_switch_ip(self):
        return self.switch_ip


def generate_uuid():
    # uuid_bytes = uuid4().bytes
    # print("gaenerated uuid is {}".format(uuid_bytes.hex()))
    # return int.from_bytes(uuid_bytes, "little")
    uuid_obj = uuid4()
    uuid_bytes = uuid_obj.bytes
    uuid_int = int.from_bytes(uuid_bytes, 'big')
    print(uuid_int.bit_length())

    if uuid_int.bit_length() != 128:
        print("Not 128 bit uuid integer, regenrating...")
        return generate_uuid()

    print("number of bytes in uuid is {}".format(len(uuid_bytes)))
    print("gaenerated uuid is {}".format(uuid_obj.hex))
    return uuid_int

# raw_data should be a seriealized string provided by Protobuf
def send_packets(local_ip, switch_ip, src_GdpName, dst_GdpName, serialized_string):
    # dissect raw data if needed
    max_payload_size_per_packet = 500
    chunks = [serialized_string[i: i+max_payload_size_per_packet] for i in range(0, len(serialized_string), max_payload_size_per_packet)]
    # print([len(chunk) for chunk in chunks])
    series_uuid = generate_uuid()
    num_packets = len(chunks)
    print(num_packets)   
    # packets need to be sent
    packet_list = []

    

    for i in range(num_packets):
        chunk = chunks[i]
        packet_no = i + 1
        packet = Ether(dst = 'ff:ff:ff:ff:ff:ff') / \
                IP(src=local_ip, dst=switch_ip)/ \
                    UDP(sport=31415, dport=31415)/ \
                        GDP(src_gdpname=src_GdpName, dst_gdpname=dst_GdpName, action=3, data_len=len(chunk), uuid=series_uuid, packet_no=packet_no, num_packets=num_packets)/ \
                            chunk
        # print(packet.layers())
        # print(packet.getlayer(GDP).action)
        # packet.getlayer(GDP).uuid = packet.getlayer(GDP).uuid & 0x00000000000000000000000000000000
        # packet.getlayer(GDP).uuid = series_uuid & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        # print(packet.getlayer(GDP).uuid.to_bytes(16, 'big').hex())
        packet_list.append(packet)


        
    
    # print(list(map(lambda x: len(x.getlayer(GDP).load), packet_list)))
    

    
    packet_sniffer = PacketSniffer(switch_ip=switch_ip, uuid=series_uuid, num_packets=num_packets)
    def for_each(packet):
        # print("Packet come in.....")
        if packet.haslayer(GDP) and packet.getlayer(GDP).uuid == series_uuid:
            # print(packet.layers())
            received_no_array = packet_sniffer.get_received_no_list()
            curr_packet_no = packet.getlayer(GDP).packet_no 
            if received_no_array[curr_packet_no - 1] == 0:
                received_no_array[curr_packet_no - 1] = 1
                packet_sniffer.get_packet_pool().append(packet)
        
    def is_to_stop(packet):
        return len(packet_sniffer.get_packet_pool()) == num_packets

    t = threading.Thread(target=packet_sniffer.start_sniff, args=(for_each, is_to_stop))
    # t = multiprocessing.Process(target=packet_sniffer.start_sniff, args=(for_each, is_to_stop))
    t.start()


    # yield to the sniffing thread
    time.sleep(0.1)
    

    # start_sending
    for i in range(len(packet_list)):
        # print("Sending packet {}".format(i+1))
        sendp(packet_list[i])
    
    # block until all responding packets are received
    while True:
        t.join(5)
        if t.is_alive():
            print("Thread is still running...")
        else:
            # print("In total, received " + str(len(packet_sniffer.get_packet_pool())) + " packets")
            break
    
    # sort and reassemble data
    # print([len(x.getlayer(GDP).load) for x in packet_sniffer.get_packet_pool()])
    sorted_packet = sorted(packet_sniffer.get_packet_pool(), key=lambda p: p.getlayer(GDP).packet_no)
    # print(list(map(lambda x: len(x[GDP].payload), sorted_packet)))
    sorted_data = list(map(lambda x: x.getlayer(GDP).load, sorted_packet))


    # print([len(x) for x in sorted_data])

    # orig_data = bytearray(sorted_data[0])
    # for i in range(1, len(sorted_data)):
    #     # print(type(sorted_data[i]),sorted_data[i])

    #     orig_data.append(sorted_data[i])
    orig_data = reduce(lambda x, y: x+y, sorted_data)
    return orig_data



if __name__ == "__main__":
    local_ip = get_local_ip()

    curr_time = datetime.now()
    string_to_hash = str(curr_time) + str(local_ip)
    GdpName = hashlib.sha256(string_to_hash.encode('utf-8'))
    # We need human-readable hex string for GdpName instead of bytes 
    local_gdp_name_hex = GdpName.hexdigest()
    print(local_gdp_name_hex)
    GdpName_in_byte = GdpName.digest()

    GdpName_in_byte = int.from_bytes(GdpName_in_byte, "big")
    # print(GdpName_in_byte)

    dst_name = int.from_bytes(bytes.fromhex("ec1063741490a1e34052b72fb4e63c615bcfe4588fc8138784033549c8812d47"), "big")
    # print(dst_name)

    # serialized_string = b''
    # msg = GdpMsg.GdpMsg()
    # msg.packet_no = 1
    # msg.num_packet = 1
    # msg.content = "What a messyessy codeWhatessy codeWhatessy codeWhatessy codeWhat codeWhessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatessy codeWhatat a messy code! What a messy code! What a messy code! What a messy code! What a messy code! What a messy code! "
    # msg.protocol_type = "custom protocol"

    # reserialized = msg.SerializeToString()
    # print("The serialized object is {}".format(reserialized))

    deserialized = os.urandom(8000)
   

    data_returned = send_packets(local_ip, "128.32.37.42", GdpName_in_byte, dst_name, deserialized)
    print(data_returned == deserialized)

    

    # print("Got Data back: {}".format(data_returned))

    # msg_2 = GdpMsg.GdpMsg()

    # msg_2.ParseFromString(data_returned)
    # assert(msg_2 == msg)
