import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, parse_qsl

from util import log


class HTTPService:

    def __init__(self, lobby_server, host, http_port) -> None:
        super().__init__()

        class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

            def games(self, params):
                print("Will return games...", params)
                try:
                    game_id = int(params["game_id"][0])
                except KeyError:
                    game_id = -1

                print("game_id:", game_id)

                if game_id == -1:
                    return {}

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()

                lobby_server.mutex.acquire()

                try:
                    import datetime
                    games_dict = [{
                        "ip": x.addr_formatted(),
                        "game_id": x.game_id,
                        "info_string": x.info_string,
                        "internal_ip": x.internal_addr_formatted(),
                        "name": x.name,
                        "num_players": x.num_players
                    } for x in lobby_server.servers if x.timestamp > datetime.datetime.now() and x.game_id == game_id]
                finally:
                    lobby_server.mutex.release()

                return {
                    "games": games_dict
                }


            def do_GET(self):

                x = urlparse(self.path)
                params = parse_qs(x.query)
                # print(x)
                result = {}

                if x.path == "/games":
                    result = self.games(params)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode(encoding='utf_8'))



        httpd = HTTPServer((host, http_port), SimpleHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()

        log("HTTP Server started on port {}".format(http_port))
