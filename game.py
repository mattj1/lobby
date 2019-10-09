import datetime

from util import inttoip


class Game:

    def __init__(self):
        self.addr = 0
        self.port = 0
        self.game_id = 0

        self.server_id = 0
        self.internal_addr = 0
        self.internal_port = 0
        self.timestamp = None
        self.info_string = ""

        self.sv_dedicated = False
        self.sv_demo = False
        self.name = "unnamed"
        self.game_type = 0
        self.num_players = 0
        self.num_player_joins = 0
        self.net_protocol = 0

    @staticmethod
    def dict_from_info_string(info_string):
        # skip the first and last backslash
        arr = info_string[1:-1].split("\\")

        d = {}
        for i in range(0, len(arr), 2):
            d[arr[i]] = arr[i + 1]

        return d

    def addr_formatted(self):
        return "{}:{}".format(inttoip(self.addr), self.port)

    def internal_addr_formatted(self):
        return "{}:{}".format(inttoip(self.internal_addr), self.internal_port)

    def update(self, info_string):
        info_dict = self.dict_from_info_string(info_string)

        # should we search by internal_ip?

        self.sv_dedicated = 0
        self.sv_demo = 0
        self.name = ""
        self.game_type = 4
        self.num_players = 0
        self.num_player_joins = 0
        self.net_protocol = 0

        if 'l_info' in info_dict:
            if int(info_dict['l_info']) & 0x02:
                self.sv_dedicated = 1

            if int(info_dict['l_info']) & 0x04:
                self.sv_demo = 1

        if 'l_n' in info_dict:
            self.name = info_dict['l_n']

        if 'l_t' in info_dict:
            self.game_type = info_dict['l_t']

        if 'l_p' in info_dict:
            self.num_players = info_dict['l_p']

        if 'l_j' in info_dict:
            self.num_player_joins = info_dict['l_j']

        if 'l_np' in info_dict:
            self.net_protocol = info_dict['l_np']

        self.info_string = info_string

        self.timestamp = datetime.datetime.now() + datetime.timedelta(seconds=15)
