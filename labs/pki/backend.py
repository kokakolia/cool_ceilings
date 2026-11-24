"""A single Unix-socket endpoint and a long response for the emergency-stop check."""

import socketserver
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.client_address = ("unix", 0)
        super().setup()

    def do_GET(self):
        body = b"order ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body) + (1 if self.path == "/hold" else 0)))
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
            if self.path == "/hold":
                time.sleep(60)
                self.wfile.write(b".")
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    path = Path("/sockets/order.sock")
    path.unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(str(path), Handler) as server:
        path.chmod(0o666)
        server.serve_forever()
