import cgi
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, parse_qsl

# from test import Lobby
from util import log


class HTTPService:

    def __init__(self, lobby_server, host, http_port) -> None:
        super().__init__()

        class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

            # def end_headers(self):
            #     self.send_header('Access-Control-Allow-Origin', '*')
            #     super().end_headers()

            def game_id_from_params(self, params):
                try:
                    return str(params["game_id"][0])
                except KeyError:
                    pass

                return None

            def games(self, params):

                game_id = self.game_id_from_params(params)

                print("game_id:", game_id)

                if not game_id:
                    return {}

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

            def totalplayers(self, params):

                np = 0

                game_id = self.game_id_from_params(params)

                print("game_id:", game_id)

                if game_id:
                    for s in lobby_server.active_servers_for_game_id(game_id):
                        np = np + int(s.num_players)

                return {"totalplayers": np}

            def peerjs_heartbeat(self, urlparams, obj):

                lobby_server.mutex.acquire()

                info_string = obj["info_string"]
                peer_id = obj["peer_id"]
                game_id = obj["game_id"]

                try:
                    server = lobby_server.get_server(peer_id, 0, game_id)

                    if not server:
                        server = lobby_server.insert_server(peer_id, 0, game_id, "", "", info_string)

                    server.update(info_string)

                finally:
                    lobby_server.mutex.release()

                return {
                    "info": "heartbeat"
                }

            def do_POST(self):
                post_data = self.rfile.read(int(self.headers['Content-Length']))  # <--- Gets the data itself
                # print("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                #              str(self.path), str(self.headers), post_data.decode('utf-8'))

                x = urlparse(self.path)
                urlparams = parse_qs(x.query)
                print(x)

                print("urlparams: ", urlparams)

                obj = json.loads(post_data)
                print(obj)


                result = {}

                if x.path == "/peerjs_heartbeat":
                    result = self.peerjs_heartbeat(urlparams, obj)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps(result).encode(encoding='utf_8'))

            def do_GET(self):

                x = urlparse(self.path)
                params = parse_qs(x.query)
                # print(x)
                result = {}

                if x.path == "/games":
                    result = self.games(params)

                if x.path == "/totalplayers":
                    result = self.totalplayers(params)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode(encoding='utf_8'))

            def _send_cors_headers(self):
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'content-type')

            def do_OPTIONS(self):
                # Send allow-origin header for preflight POST XHRs.
                from http import HTTPStatus
                # self.send_response(HTTPStatus.NO_CONTENT.value)
                self.send_response(200)
                self._send_cors_headers()
                self.end_headers()

        httpd = HTTPServer((host, http_port), SimpleHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = False
        thread.start()

        log("HTTP Server started on port {}".format(http_port))
