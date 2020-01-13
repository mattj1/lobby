import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from util import log


class HTTPService:

    def __init__(self, lobby_server, host, http_port) -> None:
        super().__init__()

        class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()

                lobby_server.mutex.acquire()

                try:
                    import datetime
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

        httpd = HTTPServer((host, http_port), SimpleHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()

        log("HTTP Server started on port {}".format(http_port))
