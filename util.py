import struct
from socket import *


def inttoip(ip):
    return inet_ntoa(struct.pack('!L', ip))


def ip_to_int(ip):
    return struct.unpack("!L", inet_aton(ip))[0]
