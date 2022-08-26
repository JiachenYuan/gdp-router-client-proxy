from scapy.all import *
from utils import *
import threading




class DataAssembler():
    def __init__(self):
        # map from series uuid to a list of received packet data for this series
        self.series_packets = dict()
        # map from series uuid to assembled payload 
        self.series_payload = dict()
    
    def put_series_data(self, gdp_packet):
        '''
        Extract data from gdp_packet and put in series_packets.
        If all packets are received for this series, move complete payload to series_payload.
        '''
        if not gdp_packet.haslayer(GDP):
            return
        gdp_layer = gdp_packet.getlayer(GDP)
        packet_num = gdp_layer.packet_no
        num_packets = gdp_layer.num_packets
        series_uuid = gdp_layer.uuid

        if series_uuid in self.series_packets.keys():
            data_list = self.series_packets[series_uuid]
            index_in_list = packet_num - 1 # We do this because packet_num starts from 1 instead of 0 for each series
            if data_list[index_in_list] == None:
                data_list[index_in_list] = gdp_layer.load
                # Assemble data and move to series_payload if all packets are presented
                if len(data_list) == num_packets:
                    assembled_data = reduce(lambda x, y: x+y, data_list)
                    self.series_payload[series_uuid] = assembled_data
                    self.series_packets.pop(series_uuid)

                    print(assembled_data)

        else:
            self.series_packets[series_uuid] = [None]*num_packets
            index_in_list = packet_num - 1
            self.series_packets[series_uuid][index_in_list] = gdp_layer.load



def start_sniffing(for_each):
    '''
    Start packet sniffing.
      for_each: a function that will be applied to every received packet. 
    '''
    sniff(prn=for_each)

def start_listening(switch_ip):
    '''
    Listen for packets coming from switch_ip, 
    assmeble the packets according to series uuid, 
    and finally store the data in a DataAssembler
    '''
    # todo: Register current receiver to Switch
    local_ip = get_local_ip()
    local_gdpname = generate_gdpname(local_ip)
    register_proxy(local_ip, switch_ip, local_gdpname)

    data_assembler = DataAssembler()
    
    t = threading.Thread(target=start_sniffing, args=(lambda packet: data_assembler.put_series_data(packet)))
    t.start()

    while True:
        t.join(5)
        if t.is_alive():
            print(data_assembler.series_payload)
        else:
            print("This thread exited unexpectedly")
            break
