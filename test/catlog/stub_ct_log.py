import base64
import functools
import hashlib
import http
import http.server
import json
import threading
import urllib.parse

from . import cert_encoding

STUB_KEY = base64.b64encode(b"key-doesnt-matter").decode('utf-8')
STUB_KEY_ID = hashlib.sha256(base64.b64decode(STUB_KEY)).digest()


class _StubCtHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def __init__(self, *args, ct_log=None, **kwargs):
        self.ct_log = ct_log
        super().__init__(*args, **kwargs)

    def do_GET(self):
        path_parts = self.path.split('?', 1)
        path = path_parts[0]
        if len(path_parts) > 1:
            query = urllib.parse.parse_qs(path_parts[1])
        else:
            query = []

        if path == "/ct/v1/get-sth":
            response = '{"tree_size":1000}'
        elif path == "/ct/v1/get-entries":
            entry_id = int(query['start'][0])
            if entry_id < len(self.ct_log.entries):
                response = json.dumps({
                    "entries": [
                        {
                            "leaf_input": base64.b64encode(self.ct_log.entries[entry_id]).decode('utf-8')
                        }
                    ]
                })
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND, "File not found")
                return
        elif path == "/ct/v1/get-proof-by-hash":
            hash = query['hash'][0]
            if hash in self.ct_log.hashes:
                response = json.dumps({
                    "leaf_index": self.ct_log.hashes[hash]
                })
            else:
                self.send_error(http.HTTPStatus.NOT_FOUND, "File not found")
                return
        else:
            self.send_error(http.HTTPStatus.NOT_FOUND, "File not found")
            return

        response_bytes = response.encode('utf-8')
        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", len(response_bytes))
        self.end_headers()

        self.wfile.write(response_bytes)
        self.wfile.flush()


class StubCtLog:
    def __init__(self):
        self.hashes = {}
        self.entries = []

        server_address = ('127.0.0.1', 0)
        self._httpd = http.server.HTTPServer(server_address, functools.partial(_StubCtHTTPRequestHandler, ct_log=self))
        threading.Thread(target=self._httpd.serve_forever).start()

        # Inject into all_logs. First load all logs...
        cert_encoding.get_all_logs()
        # Then inject this into the logs
        cert_encoding._all_logs["logs"].append({
            "url": "http://localhost:{}/".format(self._httpd.server_port),
            "key": STUB_KEY
        })

    def port(self):
        return self._httpd.server_port

    def submit(self, cert: bytes, issuer: bytes):
        leaves = cert_encoding.cert_to_merkle_tree_leaves(cert, issuer)
        for leaf in leaves:
            if leaf[0] == STUB_KEY_ID:
                index = len(self.entries)
                self.entries.append(leaf[1])
                leaf_hash = hashlib.sha256(b"\x00" + leaf[1]).digest()
                self.hashes[base64.b64encode(leaf_hash).decode('utf-8')] = index

    def stop(self):
        self._httpd.shutdown()
