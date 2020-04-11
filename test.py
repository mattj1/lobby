import datetime
import getopt
import struct
import sys
import threading
import time

from bitstring import ConstBitStream

from HTTPService import HTTPService
from InputThread import InputThread
from game import Game
from util import log


def timer_sec():
    return int(round(time.time()))


def timer_ms():
    return int(round(time.time() * 1000))


class int32(object):
    def __init__(self):
        self.num_bits = 32


class uint:
    def __init__(self, num_bits):
        self.num_bits = num_bits


class v_uint(object):
    def __init__(self):
        pass


class lidgrenStr(object):
    def __init__(self):
        pass

class nullTerminatedStr(object):
    def __init__(self):
        pass

def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


def swap16(i):
    return ((i & 0xff00) >> 8) | ((i & 0x00ff) << 8)


def write_uint_factory(instance):
    num_bits = instance.num_bits

    def write_uint(stream, data):
        if isinstance(data, list):
            for integer in data:
                write_uint(stream, integer)
        else:
            integer = int(data)
            if integer < 0:
                error = "negative integers cannot be encoded"
                raise ValueError(error)
            bools = []
        for _ in range(num_bits):
            bools.append(integer & 1)
            integer = integer >> 1
        bools.reverse()
        stream.write(bools, bool)

    return write_uint


def read_uint_factory(instance):  # use the name factory ?
    num_bits = instance.num_bits

    def read_uint(stream, n=None):
        if n is None:
            integer = 0
            for _ in range(num_bits):
                integer = integer << 1
                if stream.read(bool):
                    integer += 1
            return integer
        else:
            integers = [read_uint(stream) for _ in range(n)]
            return integers

    return read_uint


def read_v_uint(stream: ConstBitStream, n=None):
    if n is None:
        integer = 0

        while True:
            # b = stream.read(uint(8))
            b = stream.read('uint:8')
            # print "read v uint byte: ", hex(b)
            # print "read v uint byte (int): ", b
            integer = (integer << 7) | (b & 0x7f)
            if b & 0x80 != True:
                break
        # print "return ", integer
        return integer
    else:
        return [read_v_uint(stream) for _ in range(n)]


def read_v_uint_factory(instance):
    return read_v_uint


def read_lidgren_str(msg: ConstBitStream, n=None):
    if n is None:
        length = read_v_uint(msg)
        # length = stream.read(v_uint())
        # return "".join(chr(stream.read(v_uint())) for _ in range(length))
        return "".join(chr(read_v_uint(msg)) for _ in range(length))
    else:
        strings = [read_lidgren_str(msg) for _ in range(n)]
        return strings

# def read_lidgrenStr_factory(instance):
#     def read_lidgrenStr(stream, n=None):

#
#     return read_lidgrenStr


def write_lidgrenStr_factory(instance):
    def write_lidgrenStr(stream, data):
        if isinstance(data, list):
            for string in data:
                write_lidgrenStr(stream, string)
        else:
            stream.write(uint(8), len(data))  # Warning, is not variable-length int. Max string length is 127!

            for c in stream:
                stream.write(uint(8), c)

    return write_lidgrenStr


def read_nullTerminatedStr_factory(instance):
    def read_nullTerminatedStr(stream, n=None):

        if n is None:
            s = ""
            while True:
                ch = stream.read(v_uint())
                if ch == 0:
                    return s

                s += chr(ch)

            # return "".join(chr(stream.read(v_uint())) for _ in range(length))
        else:
            strings = [read_nullTerminatedStr(stream) for _ in range(n)]
            return strings

    return read_nullTerminatedStr


# bitstream.register(uint, reader=read_uint_factory, writer=write_uint_factory)
# bitstream.register(v_uint, reader=read_v_uint_factory)
# bitstream.register(lidgrenStr, reader=read_lidgrenStr_factory, writer=write_lidgrenStr_factory)
# bitstream.register(nullTerminatedStr, reader=read_nullTerminatedStr_factory, writer=None)


# def sqlSafe(str):
#     global db
#     return db.escape_string(str)


class Lobby:
    servers: [Game] = []

    def get_server(self, ip, port, game_id):
        for s in self.servers:
            if s.addr == ip and s.port == port and s.game_id == game_id:
                return s

        return None

    def server_exists(self, ip, port, game_id):
        if self.get_server(ip, port, game_id):
            return True

        return False

    def insert_server(self, ip, port, game_id, internal_addr, internal_port, info_string):
        server = Game()
        server.addr = ip
        server.port = port
        server.game_id = game_id
        server.internal_addr = internal_addr
        server.internal_port = internal_port
        server.info_string = info_string

        server.timestamp = datetime.datetime.now() + datetime.timedelta(seconds=15)

        self.servers.append(server)

        print("Added server: {}:{} {}".format(ip, port, info_string))

        return server

    def remove_server_with_id(self, game_id):
        self.servers = [x for x in self.servers if x.game_id is not game_id and x.timestamp < datetime.datetime.now()]

    def remove_old_servers(self):
        self.servers = [x for x in self.servers if x.timestamp < datetime.datetime.now()]

        # query = "delete from games where timestamp < now() and game_id='{}'".format(game_id)

    def __init__(self, host, udp_port, http_port):

        self.mutex = threading.Lock()

        log("Host: {}, UDP: {}, HTTP: {}".format(host, udp_port, http_port))

        from UDPService import UDPService, LidgrenPacketHandler#, SpectrePacketHandler
        UDPService(host, udp_port, packet_handler=LidgrenPacketHandler(lobby_server=self))
        # UDPService(host, udp_port, packet_handler=SpectrePacketHandler(lobby_server=self))

        http_service = HTTPService(host=host, http_port=http_port, lobby_server=self)

        # httpd.serve_forever()

        thread = InputThread(lobby_server=self)
        thread.start()


def main(argv):
    host = "localhost"
    udp_port = 27713
    tcp_port = 8001

    def print_help():
        print('test.py -h <host> -u <udp_port> -t <tcp_port>')

    try:
        opts, args = getopt.getopt(argv, "?h:u:t:", ["help", "host=", "udp-port=", "tcp-port"])
    except getopt.GetoptError:
        pass
        # print_help()
        # sys.exit(2)

    for opt, arg in opts:
        if opt == '-?':
            print_help()
            sys.exit()
        elif opt in ("-h", "--host"):
            host = arg
        elif opt in ("-u", "--udp-port"):
            udp_port = int(arg)
        elif opt in ("-t", "--tcp-port"):
            tcp_port = int(arg)

    global lobby_server
    lobby_server = Lobby(host, udp_port, tcp_port)


if __name__ == "__main__":
    main(sys.argv[1:])
