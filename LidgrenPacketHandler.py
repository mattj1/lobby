from _socket import ntohs
from struct import pack

import bitstring

from UDPService import BasePacketHandler
from test import swap16, swap32, read_lidgren_str
from util import ip_to_int, log, inttoip


class LidgrenPacketHandler(BasePacketHandler):

    def handle(self, sck, msg: bitstring.ConstBitStream, client_address):
        # msgType = msg.read(uint(8), 1)
        msgType = msg.read('uint:8')
        msg.bitpos += 16
        # msg.read('uint:8')
        # msg.read('uint:8')
        length = swap16(msg.read('uint:16'))

        # msg.read(uint(8))
        # msg.read(uint(8))

        # length = msg.read(uint(16))
        # log("length: %s" % hex(length))

        # length = swap16(length)
        # log("length: %s (%d bytes)" % (hex(length), length >> 3))
        log("{}:{} wrote {} bytes. Payload size: {} bytes".format(
            client_address[0],
            client_address[1],
            len(msg) >> 3,
            length >> 3))

        length >>= 3

        packet_type = msg.read('uint:8')
        # packet_type = msg.read(uint(8))

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

    def processHeartbeat(self, msg: bitstring.ConstBitStream, client_address):

        # Server ID. Should be random
        server_id = swap32(msg.read('uint:32'))

        # Game ID (Hardcoded) - so lobby can support different games/products
        host_game_id = swap32(msg.read('uint:32'))

        # Internal endpoint of host
        addressBytesLength = msg.read('uint:8')
        internal_addr = msg.read('uint:32')
        internal_port = ntohs(msg.read('uint:16'))

        # info string
        info_string = read_lidgren_str(msg) #msg.read(lidgrenStr())

        ip = ip_to_int(client_address[0])
        port = client_address[1]

        print("Heartbeat from {}: Server ID: {}, Host Game ID: {}".format(
              client_address, server_id, host_game_id))

        # print("Heartbeat from", client_address, ":", server_id, host_game_id,
        #       "{}:{}".format(inttoip(ip), port),
        #       "{}:{}".format(inttoip(internal_addr), internal_port),
        #       info_string)

        # if this server exists, just update the existing entry

        self.update(ip, port, host_game_id, internal_addr, internal_port, info_string)

    def processPunchThrough(self, sck, msg, client_address):

        # Internal endpoint of client
        addressBytesLength = msg.read('uint:8')
        internal_addr = msg.read('uint:32')
        internal_port = ntohs(msg.read('uint:16'))

        # Host address
        addressBytesLength = msg.read('uint:8')
        dest_addr = msg.read('uint:32')
        dest_port = ntohs(msg.read('uint:16'))

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

