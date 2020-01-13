import threading
from typing import Optional, Callable, Any, Iterable, Mapping


class InputThread(threading.Thread):
    lobby_server = None

    def __init__(self, lobby_server) -> None:
        super().__init__()

        self.lobby_server = lobby_server

    def run(self):
        while True:
            line = input(">")

            print(self.lobby_server)

            if line == 'quit':
                return

