import struct
import time
from datetime import datetime
from socket import *


def inttoip(ip):
    return inet_ntoa(struct.pack('!L', ip))


def ip_to_int(ip):
    return struct.unpack("!L", inet_aton(ip))[0]


def log(message):
    ts = time.time()
    st = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print("[{}] {}".format(st, message))
