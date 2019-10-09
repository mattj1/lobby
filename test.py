import getopt
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from socket import *
import threading
import socketserver as SocketServer
import time
import datetime
import struct
from struct import *
import bitstream
from bitstream import BitStream

from game import Game
from util import ip_to_int, inttoip


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


def read_v_uint_factory(instance):
    def read_v_uint(stream, n=None):
        if n is None:
            integer = 0

            while True:
                b = stream.read(uint(8))
                # print "read v uint byte: ", hex(b)
                # print "read v uint byte (int): ", b
                integer = (integer << 7) | (b & 0x7f)
                if (b & 0x80 != True):
                    break
            # print "return ", integer
            return integer
        else:
            integers = [read_v_uint(stream) for _ in range(n)]

    return read_v_uint


def read_lidgrenStr_factory(instance):
    def read_lidgrenStr(stream, n=None):
        if n is None:
            length = stream.read(v_uint())
            return "".join(chr(stream.read(v_uint())) for _ in range(length))
        else:
            strings = [read_lidgrenStr(stream) for _ in range(n)]
            return strings

    return read_lidgrenStr


def write_lidgrenStr_factory(instance):
    def write_lidgrenStr(stream, data):
        if isinstance(data, list):
            for string in data:
                write_lidgrenStr(stream, string)
        else:
            stream.write(uint(8), len(data))  # Warning, is not variable-length int. Max string length is 127!

            for c in string:
                stream.write(uint(8), c)

    return write_lidgrenStr


bitstream.register(uint, reader=read_uint_factory, writer=write_uint_factory)
bitstream.register(v_uint, reader=read_v_uint_factory)
bitstream.register(lidgrenStr, reader=read_lidgrenStr_factory, writer=write_lidgrenStr_factory)


# def sqlSafe(str):
#     global db
#     return db.escape_string(str)

def log(str):
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print("[{}] {}".format(st, str))


class MyUDPHandler(SocketServer.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.idx = 0
        self.data = ""
        # print "UDP server started"

    # def readString(self, data):
    #
    #     # l = unpack('H', self.getBytes(2))[0]
    #
    #     # print "String length: %d" % l
    #     l = self.data[self.idx:].find('\x00');
    #
    #     str = self.data[self.idx: self.idx + l]
    #     self.idx += (l + 1)
    #
    #     return str

    # def getBytes(self, numBytes):
    #     bytes = self.data[self.idx: self.idx + numBytes]
    #     self.idx += numBytes
    #     return bytes

    # def runQuery(self, query):
    #     global db
    #
    #     try:
    #         db.ping()
    #     except (AttributeError, MySQLdb.OperationalError):
    #         print("Reconnecting...")
    #         connectToDB()
    #
    #     if self.logNextQuery:
    #         log("Run query: {}".format(query))
    #
    #     self.logNextQuery = False
    #
    #     cursor = db.cursor()
    #     cursor.execute(query)
    #     db.commit()
    #
    #     return cursor

    # def runQueryAndClose(self, query):
    #     cursor = self.runQuery(query)
    #     cursor.close()

    def processHeartbeat(self, msg: BitStream):

        # Server ID. Should be random
        server_id = swap32(msg.read(uint(32)))

        # Game ID (Hardcoded) - so lobby can support different games/products
        host_game_id = swap32(msg.read(uint(32)))

        # Internal endpoint of host
        addressBytesLength = msg.read(uint(8))
        internal_addr = msg.read(uint(32))
        internal_port = ntohs(msg.read(uint(16)))

        # info string
        info_string = msg.read(lidgrenStr())
        ip = ip_to_int(self.client_address[0])

        port = self.client_address[1]
        print("Client address: {}".format(self.client_address))

        print("Heartbeat:", server_id, host_game_id,
              "{}:{}".format(inttoip(ip), port),
              "{}:{}".format(inttoip(internal_addr), internal_port),
              info_string)

        # if this server exists, just update the existing entry

        lobby_server.mutex.acquire()

        try:
            server = lobby_server.get_server(ip, port, host_game_id)

            if not server:
                server = lobby_server.insert_server(ip, port, host_game_id, internal_addr, internal_port, info_string)

            server.update(info_string)
        finally:
            lobby_server.mutex.release()

    def processPunchThrough(self, msg):

        # Internal endpoint of client
        addressBytesLength = msg.read(uint(8))
        internal_addr = msg.read(uint(32))
        internal_port = ntohs(msg.read(uint(16)))

        # Host address
        addressBytesLength = msg.read(uint(8))
        dest_addr = msg.read(uint(32))
        dest_port = ntohs(msg.read(uint(16)))

        # External endpoint of client
        client_external_address = ip_to_int(self.client_address[0])
        client_external_port = self.client_address[1]

        print("punch-through: dest: {}:{}".format(inttoip(dest_addr), dest_port))

        # Host internal
        # print("TODO: punch-through should require game/server ID as well...")

        server = lobby_server.get_server(dest_addr, dest_port, 101)

        if not server:
            return

        host_internal_addr = server.internal_addr
        host_internal_port = server.internal_port

        print("host internal: ", host_internal_addr, host_internal_port)

        # print "Host address: {} {}".format(dest_addr, repr(dest_addr))
        print("Sending punch-through:  --->")

        print("Host external: {}:{}".format(inttoip(dest_addr), dest_port))
        print("Host internal: {}:{}".format(inttoip(host_internal_addr), host_internal_port))
        print("Client external: {}:{}".format(inttoip(client_external_address), client_external_port))
        print("Client internal: {}:{}".format(inttoip(internal_addr), internal_port))

        # To client:
        pck = b"\x8b"  # packet type 139
        pck += b"\x00\x00"  # reliable seq (since packet type is 139)

        payload = b"\x00"  # byte:0 (Designated Client)

        # host Internal
        payload += b"\x04" + pack('!L', host_internal_addr) + pack('!H', host_internal_port)

        # host External
        payload += b"\x04" + pack('!L', dest_addr) + pack('!H', dest_port)
        payload += b"\x04" + bytes("test", "utf-8")

        payload_len_bits = len(payload) << 3
        pck += pack('!H', swap16(payload_len_bits))
        pck += payload

        # send this packet to the client
        addr = (inttoip(client_external_address), client_external_port)
        sck = self.request[1]
        sck.sendto(bytearray(pck), addr)

        # -------------

        # To host:
        pck = b"\x8b"  # packet type 139
        pck += b"\x00\x00"  # reliable seq (since packet type is 139)

        payload = b"\x01"  # byte:1

        # client Internal
        payload += b"\x04" + pack('!L', internal_addr) + pack('!H', internal_port)

        # client External
        payload += b"\x04" + pack('!L', client_external_address) + pack('=H', client_external_port)

        # token (string)
        payload += b"\x04" + bytes("test", "utf-8")

        payload_len_bits = len(payload) << 3
        print("payload: ", type(payload), len(payload), payload)
        print("payload len: bits: {} bytes: {} ".format(payload_len_bits, payload_len_bits >> 3))

        pck += pack('!H', swap16(payload_len_bits))
        pck += payload

        # send this packet to the host
        addr = (inttoip(dest_addr), dest_port)
        sck = self.request[1]
        sck.sendto(bytearray(pck), addr)

    # PER MESSAGE:
    # 7 bits - NetMessageType
    # 1 bit - Is a message fragment?

    # [8 bits NetMessageLibraryType, if NetMessageType == Library]

    # [16 bits sequence number, if NetMessageType >= UserSequenced]

    # 8/16 bits - Payload length in bits (variable size ushort)

    # [16 bits fragments group id, if fragmented]
    # [16 bits fragments total count, if fragmented]
    # [16 bits fragment number, if fragmented]

    # [x - Payload] if length > 0

    def handle(self):
        self.data = self.request[0]

        log("{}:{} wrote {} bytes:".format(self.client_address[0], self.client_address[1], len(self.data)))

        msg = BitStream()
        msg.write(self.data, bytes)

        # msg = BitStream(self.data)

        msgType = msg.read(uint(8), 1)
        msg.read(uint(8))
        msg.read(uint(8))

        length = msg.read(uint(16))
        log("length: %s" % hex(length))

        length = swap16(length)
        log("length: %s (%d bytes)" % (hex(length), length >> 3))

        length >>= 3

        packet_type = msg.read(uint(8))

        if packet_type == 0:
            self.processHeartbeat(msg)

        if packet_type == 4:
            self.processPunchThrough(msg)

        # #print ":".join("{0:x}".format(ord(c)) for c in self.data)
        #
        # l = unpack('H', self.getBytes(2))[0]
        #
        # packet_type = unpack('b', self.getBytes(1))[0]
        #
        # #print "packet len: %d" % l
        # #print "packet_type: %d" % packet_type
        #
        # if packet_type == 0:
        #     self.processHeartbeat()


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

    # def internal_IP_for_server(self, ip, port):
    #     query = "select internal_ip from games where ip2 = \'{}\' and port = {}".format(ip, port)
    #     cursor = self.runQuery(query)
    #
    #     result = None
    #
    #     if cursor.rowcount > 0:
    #         results = cursor.fetchall()
    #         for row in results:
    #             result = row[0].split(":")
    #             break
    #
    #     cursor.close()
    #
    #     return result

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

    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            lobby_server.mutex.acquire()

            try:
                games_dict = [{
                    "ip": x.addr_formatted(),
                    "info_string": x.info_string,
                    "internal_ip": x.internal_addr_formatted(),
                    "name": x.name,
                    "num_players": x.num_players,
                } for x in lobby_server.servers if x.timestamp > datetime.datetime.now()]
            finally:
                lobby_server.mutex.release()

            json_string = json.dumps({
                "games": games_dict}
            )

            self.wfile.write(json_string.encode(encoding='utf_8'))
            # self.wfile.write(b'Hello, world!')

    def __init__(self, host, udp_port, http_port):

        self.mutex = threading.Lock()

        print("Host: {}, UDP: {}, HTTP: {}".format(host, udp_port, http_port))

        udpserver = SocketServer.UDPServer((host, udp_port), MyUDPHandler)
        thread = threading.Thread(target=udpserver.serve_forever)
        thread.daemon = True
        thread.start()

        log("UDP Server started on port {}".format(udp_port))

        httpd = HTTPServer((host, http_port), Lobby.SimpleHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        # thread.daemon = True
        thread.start()
        log("HTTP Server started on port {}".format(http_port))
        # httpd.serve_forever()


lobby_server: Lobby = None


def main(argv):
    host = "localhost"
    udp_port = 27713
    tcp_port = 8000

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

    # print('Input file is "', inputfile)
    # print('Output file is "', outputfile)

    global lobby_server
    lobby_server = Lobby(host, udp_port, tcp_port)


if __name__ == "__main__":
    main(sys.argv[1:])
