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


def inttoip(ip):
    return inet_ntoa(struct.pack('!I', ip))
    # return inet_ntoa(hex(int(ip))[2:].zfill(8).decode('hex'))


def ip_to_int(ip):
    # network-formatted
    return int(inet_aton(ip).encode('hex'), 16)


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
        internal_ip = "{}:{}".format(inttoip(internal_addr), internal_port)

        # info string
        info_string = msg.read(lidgrenStr())
        ip = self.client_address[0]
        port = self.client_address[1]
        print("Heartbeat:", server_id, host_game_id, ip, port, internal_ip, info_string)

        # socket = self.request[1]

        # if this server exists, just update the existing entry
        # lobby_server.remove_server_with_id(host_game_id)

        server = lobby_server.get_server(ip, port, host_game_id)

        if not server:
            server = lobby_server.insert_server(ip, port, host_game_id, internal_ip, info_string)

        server.update(info_string)

    def processPunchThrough(self, msg):
        print("punch-through:")

        # Internal endpoint of client
        addressBytesLength = msg.read(uint(8))
        internal_addr = msg.read(uint(32))
        internal_port = msg.read(uint(16))

        # External endpoint of client
        client_external_address = ip_to_int(self.client_address[0])
        client_external_port = self.client_address[1]

        # Host address
        addressBytesLength = msg.read(uint(8))
        dest_addr = msg.read(uint(32))
        dest_port = msg.read(uint(16))

        # Host internal
        print("TODO: punch-through should require game/server ID as well...")

        return

        host_internal_ip_port = lobby_server.internal_IP_for_server(inttoip(dest_addr), ntohs(dest_port))

        if host_internal_ip_port == None:
            return

        host_internal_addr = ip_to_int(host_internal_ip_port[0])
        host_internal_port = htons(int(host_internal_ip_port[1]))

        print("IP and port array: ", host_internal_ip_port)

        # print "Host address: {} {}".format(dest_addr, repr(dest_addr))
        print("Sending punch-through:  --->")

        print("Host external: {}:{}".format(inttoip(dest_addr), ntohs(dest_port)))
        print("Host internal: {}:{}".format(inttoip(host_internal_addr), ntohs(host_internal_port)))
        print("Client external: {}:{}".format(inttoip(client_external_address), client_external_port))
        print("Client internal: {}:{}".format(inttoip(internal_addr), ntohs(internal_port)))
        # return
        # To client:
        # To host:
        pck = "\x8b"  # packet type 139
        pck += "\x00\x00"  # reliable seq (since packet type is 139)

        payload = "\x00"  # byte:0 (Designated Client)

        # host Internal
        # TODO
        payload += "\x04{}".format(pack('!I', host_internal_addr))
        payload += "{}".format(pack('!H', host_internal_port))
        # host External
        payload += "\x04{}".format(pack('!I', dest_addr))
        payload += "{}".format(pack('!H', dest_port))
        payload += "\x04test"  # token (string)

        payload_len = len(payload) * 8
        pck += "{}".format(pack('!H', swap16(payload_len)))
        pck += payload

        # send this packet to the client
        sck = self.request[1]
        sck.sendto(pck, (inttoip(client_external_address), client_external_port))

        # -------------

        # To host:
        pck = "\x8b"  # packet type 139
        pck += "\x00\x00"  # reliable seq (since packet type is 139)

        payload = "\x01"  # byte:1

        # client Internal
        payload += "\x04{}".format(pack('!I', internal_addr))
        payload += "{}".format(pack('!H', internal_port))

        # client External
        payload += "\x04{}".format(pack('!I', client_external_address))
        payload += "{}".format(pack('=H', client_external_port))

        # token (string)
        payload += "\x04test"

        payload_len = len(payload) * 8
        print("payload: ", payload)
        print("payload len bytes: ", payload_len / 8)
        print("payload len bits: ", payload_len)

        pck += "{}".format(pack('!H', swap16(payload_len)))
        pck += payload

        # send this packet to the host
        sck = self.request[1]
        sck.sendto(pck, (inttoip(dest_addr), ntohs(dest_port)))
        return
        # addr:port for server to send this request to

        pck = "{}\xff\x04".format(pack('<h', 10))  # baaad. Should be network-formatted.

        # Add the address and port that this packet came from
        pck += "{}".format(pack('!I', ip_to_int(self.client_address[0])));
        pck += "{}".format(pack('!H', self.client_address[1]));

        # send: [length:10(2)]  [0xff(1)][0x04(1)][dest addr, net formatted(4)][dest port, net formatted(2)]
        # pck = "\xff\x04{}{}".format(pack('!I', iptoint(self.client_address[0])), pack('!H, socket.htons(self.client_address[1])))
        # print "packet: "
        # print ":".join("{0:x}".format(ord(c)) for c in pck)

        # socket.sendto(data.upper(), self.client_address)

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
            if s.ip == ip and s.port == port and s.game_id == game_id:
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

    def insert_server(self, ip, port, game_id, internal_ip, info_string):
        game = Game()
        game.ip = ip
        game.port = port
        game.game_id = game_id
        game.internal_ip = internal_ip
        game.info_string = info_string

        game.timestamp = datetime.datetime.now() + datetime.timedelta(seconds=15)

        self.servers.append(game)

        print("Added server: {}:{} {}".format(ip, port, info_string))

        return game

    def remove_server_with_id(self, game_id):
        self.servers = [x for x in self.servers if x.game_id is not game_id and x.timestamp < datetime.datetime.now()]

        # query = "delete from games where timestamp < now() and game_id='{}'".format(game_id)

    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            games_dict = [{
                "ip": "{}:{}".format(x.ip, x.port),
                "info_string": x.info_string,
                "internal_ip": x.internal_ip
            } for x in lobby_server.servers]

            json_string = json.dumps(games_dict)
            self.wfile.write(json_string.encode(encoding='utf_8'))
            # self.wfile.write(b'Hello, world!')

    def __init__(self, host, udp_port, http_port):

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


lobby_server = None


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

HOST = "localhost"
UDP_PORT = 27713
HTTP_PORT = 8000



