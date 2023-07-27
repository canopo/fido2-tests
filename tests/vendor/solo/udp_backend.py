import socket

import fido2.hid
from fido2.hid.base import HidDescriptor, CtapHidConnection

def open_connection(descriptor):
    return HidOverUDP(descriptor)

def get_descriptor(path):
    #                    path, vid, pid, max_in_size, max_out_size, name, serial
    return HidDescriptor(path, 0x1234, 0x5678, 64, 64, "software test interface", "12345678")

def list_descriptors():
    path = "localhost:8111"
    return [get_descriptor(path)]

def force_udp_backend():
    fido2.hid.open_connection = open_connection
    fido2.hid.get_descriptor = get_descriptor
    fido2.hid.list_descriptors = list_descriptors


class HidOverUDP(CtapHidConnection):

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 7112))
        addr, port = descriptor.path.split(":")
        port = int(port)
        self.token = (addr, port)
        self.sock.settimeout(1.0)

    def close(self):
        self.sock.close()

    def write_packet(self, packet):
        self.sock.sendto(packet, self.token)

    def read_packet(self):
        pkt, _ = self.sock.recvfrom(64)
        return pkt

