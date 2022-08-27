import hashlib
import socket
from uuid import uuid4
from scapy.all import *

# ! Adjust the order of fileds to solve the field byte shift problem



def get_local_ip():
    '''
    Get local IPv4 address in string format. e.g. 123.123.123.123
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = s.getsockname()[0]
    return local_ip_address






def generate_gdpname(local_ip):
    '''
    Generate a 256 bit GDPName for current machine based on current time and ip address,
    and print out the hex representation and return the integer representation
    '''
    curr_time = datetime.now()
    string_to_hash = str(curr_time) + str(local_ip)
    GdpName = hashlib.sha256(string_to_hash.encode('utf-8'))
    # We need human-readable hex string for GdpName instead of bytes for display purpose
    local_gdp_name_hex = GdpName.hexdigest()
    print(local_gdp_name_hex)

    GdpName_in_bytes = GdpName.digest()
    GdpName_in_int = int.from_bytes(GdpName_in_bytes, "big")
    return GdpName_in_int




def generate_uuid():
    '''
    Generate a 128-bit integer using python uuid.uuid4()
    '''
    uuid_obj = uuid4()
    uuid_bytes = uuid_obj.bytes
    uuid_int = int.from_bytes(uuid_bytes, 'big')
    print("gaenerated uuid is {}".format(uuid_obj.hex))
    return uuid_int