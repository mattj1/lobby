import socketserver as SocketServer
import threading
from struct import pack

import bitstring

from test import uint, lidgrenStr, swap32, swap16, nullTerminatedStr, read_lidgren_str
from util import log, ntohs, ip_to_int, inttoip, ntohl


class BasePacketHandler:

    def __init__(self, lobby_server) -> None:
        super().__init__()

        self.lobby_server = lobby_server

    def handle(self, sck, msg: bitstring.ConstBitStream, client_address):
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

#
# class SpectrePacketHandler(BasePacketHandler):
#     def handle(self, sck, msg: BitStream, client_address):
#         print("spectre packet {} External addr: {}".format(sck, client_address))
#
#         # length: 2 bytes
#         # Packet type: 1 byte, always 0
#         # Lobby ID: 4 bytes
#         # Info string: null-terminated characters
#
#         length = swap16(msg.read(uint(16)))
#
#         lobby_packet_version = msg.read(uint(8))
#
#         if lobby_packet_version != 1:
#             return
#
#         packet_type = msg.read(uint(8))
#
#         external_addr = ip_to_int(client_address[0])
#         external_port = client_address[1]
#
#         # Heartbeat
#         if packet_type == 0:
#             lobby_id = msg.read(msg.read(uint(32)))
#
#             internal_addr = ntohl(msg.read(uint(32)))
#             internal_port = ntohs(msg.read(uint(16)))
#
#             info_string = msg.read(nullTerminatedStr())
#
#             # print(length, packet_type, lobby_id)
#
#             print("External addr {}:{}".format(inttoip(external_addr), external_port))
#             print("Internal addr {}:{}".format(inttoip(internal_addr), internal_port))
#             print(info_string)
#
#             self.update(internal_addr, internal_port, 0, internal_addr, internal_port, info_string)
#
#         if packet_type == 4:
#             print("Punch-through")
#

        # Server should reply: [2 - length][1 - client 255][1 - 3 (lobby id)][4 - lobby id]


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

                # msg = BitStream()
                # msg.write(self.data, bytes)

                msg = bitstring.ConstBitStream(self.data)
                print(msg)

                packet_handler.handle(msg=msg, sck=self.request[1], client_address=self.client_address)

        udpserver = SocketServer.UDPServer((host, port), MyUDPHandler)
        thread = threading.Thread(target=udpserver.serve_forever)
        thread.daemon = True
        thread.start()

        log("UDP Server started on port {}".format(port))
