import socketserver as SocketServer
import threading
from struct import pack

from bitstream import BitStream

from test import uint, lidgrenStr, swap32, swap16, nullTerminatedStr
from util import log, ntohs, ip_to_int, inttoip, ntohl


class BasePacketHandler:

    def __init__(self, lobby_server) -> None:
        super().__init__()

        self.lobby_server = lobby_server

    def handle(self, sck, msg, client_address):
        pass

    def update(self, ip, port, host_game_id, internal_addr, internal_port, info_string):

        self.lobby_server.mutex.acquire()

        try:
            server = self.lobby_server.get_server(ip, port, host_game_id)

            if not server:
                server = self.lobby_server.insert_server(ip, port, host_game_id, internal_addr, internal_port,
                                                         info_string)

            server.update(info_string)
        finally:
            self.lobby_server.mutex.release()


class SpectrePacketHandler(BasePacketHandler):
    def handle(self, sck, msg: BitStream, client_address):
        print("spectre packet {} External addr: {}".format(sck, client_address))

        # length: 2 bytes
        # Packet type: 1 byte, always 0
        # Lobby ID: 4 bytes
        # Info string: null-terminated characters

        length = swap16(msg.read(uint(16)))

        lobby_packet_version = msg.read(uint(8))

        if lobby_packet_version != 1:
            return

        packet_type = msg.read(uint(8))

        external_addr = ip_to_int(client_address[0])
        external_port = client_address[1]

        # Heartbeat
        if packet_type == 0:
            lobby_id = msg.read(msg.read(uint(32)))

            internal_addr = ntohl(msg.read(uint(32)))
            internal_port = ntohs(msg.read(uint(16)))

            info_string = msg.read(nullTerminatedStr())

            # print(length, packet_type, lobby_id)

            print("External addr {}:{}".format(inttoip(external_addr), external_port))
            print("Internal addr {}:{}".format(inttoip(internal_addr), internal_port))
            print(info_string)

            self.update(internal_addr, internal_port, 0, internal_addr, internal_port, info_string)

        if packet_type == 4:
            print("Punch-through")


        # Server should reply: [2 - length][1 - client 255][1 - 3 (lobby id)][4 - lobby id]


class LidgrenPacketHandler(BasePacketHandler):

    def handle(self, sck, msg: BitStream, client_address):
        msgType = msg.read(uint(8), 1)
        msg.read(uint(8))
        msg.read(uint(8))

        length = msg.read(uint(16))
        # log("length: %s" % hex(length))

        length = swap16(length)
        # log("length: %s (%d bytes)" % (hex(length), length >> 3))
        log("{}:{} wrote {} bytes. Payload size: {} bytes".format(
            client_address[0],
            client_address[1],
            len(msg) >> 3,
            length >> 3))

        length >>= 3

        packet_type = msg.read(uint(8))

        if packet_type == 0:
            self.processHeartbeat(msg, client_address=client_address)

        if packet_type == 4:
            self.processPunchThrough(sck=sck, msg=msg, client_address=client_address)

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

    def processHeartbeat(self, msg: BitStream, client_address):

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

        ip = ip_to_int(client_address[0])
        port = client_address[1]

        print("Heartbeat from", client_address, ":", server_id, host_game_id,
              "{}:{}".format(inttoip(ip), port),
              "{}:{}".format(inttoip(internal_addr), internal_port),
              info_string)

        # if this server exists, just update the existing entry

        self.update(ip, port, host_game_id, internal_addr, internal_port, info_string)

    def processPunchThrough(self, sck, msg, client_address):

        # Internal endpoint of client
        addressBytesLength = msg.read(uint(8))
        internal_addr = msg.read(uint(32))
        internal_port = ntohs(msg.read(uint(16)))

        # Host address
        addressBytesLength = msg.read(uint(8))
        dest_addr = msg.read(uint(32))
        dest_port = ntohs(msg.read(uint(16)))

        # External endpoint of client
        client_external_address = ip_to_int(client_address[0])
        client_external_port = client_address[1]

        print("punch-through: dest: {}:{}".format(inttoip(dest_addr), dest_port))

        # Host internal
        # print("TODO: punch-through should require game/server ID as well...")

        server = self.lobby_server.get_server(dest_addr, dest_port, 101)

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
        payload += b"\x04" + pack('!L', host_internal_addr) + pack('<H', host_internal_port)

        # host External
        payload += b"\x04" + pack('!L', dest_addr) + pack('<H', dest_port)
        payload += b"\x04" + bytes("test", "utf-8")

        payload_len_bits = len(payload) << 3
        pck += pack('!H', swap16(payload_len_bits))
        pck += payload

        # send this packet to the client
        addr = (inttoip(client_external_address), client_external_port)
        print("send to client: ", addr)
        # sck = self.request[1]
        sck.sendto(bytearray(pck), addr)

        # -------------

        # To host:
        pck = b"\x8b"  # packet type 139
        pck += b"\x00\x00"  # reliable seq (since packet type is 139)

        payload = b"\x01"  # byte:1

        # client Internal
        payload += b"\x04" + pack('!L', internal_addr) + pack('<H', internal_port)

        # client External
        payload += b"\x04" + pack('!L', client_external_address) + pack('<H', client_external_port)

        # token (string)
        payload += b"\x04" + bytes("test", "utf-8")

        payload_len_bits = len(payload) << 3
        print("payload: ", type(payload), len(payload), payload)
        print("payload len: bits: {} bytes: {} ".format(payload_len_bits, payload_len_bits >> 3))

        pck += pack('!H', swap16(payload_len_bits))
        pck += payload

        # send this packet to the host
        addr = (inttoip(dest_addr), dest_port)
        print("send to server: ", addr)
        # sck = self.request[1]
        sck.sendto(bytearray(pck), addr)


class UDPService:
    def __init__(self, host, port, packet_handler) -> None:
        super().__init__()

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

                msg = BitStream()
                msg.write(self.data, bytes)

                packet_handler.handle(msg=msg, sck=self.request[1], client_address=self.client_address)

        udpserver = SocketServer.UDPServer((host, port), MyUDPHandler)
        thread = threading.Thread(target=udpserver.serve_forever)
        thread.daemon = True
        thread.start()

        log("UDP Server started on port {}".format(port))
