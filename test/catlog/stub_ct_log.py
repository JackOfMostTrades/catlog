import base64
import functools
import hashlib
import http
import http.server
import io
import json
import threading
import urllib.parse
from typing import Optional

import asn1crypto.x509

from catlog import cert_encoding
from catlog.stub_crt_sh import StubCrtSh

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


class StubCtLogList(cert_encoding.CtLogList):
    def __init__(self):
        self._log_url = None
        self._leaf_by_hash = {}
        pass

    def lookup_ct_log_by_id(self, log_id: bytes) -> Optional[str]:
        if log_id == STUB_KEY_ID:
            return self._log_url
        return None

    def lookup_ct_log_id_by_url(self, ct_log_url: str) -> Optional[bytes]:
        if ct_log_url == self._log_url:
            return STUB_KEY_ID
        return None

    def get_sth(self, ct_log, debug_file: io.IOBase = None):
        return None

    def get_leaf_by_hash(self, ct_log: str, hash: str, debug_file: io.IOBase = None) -> Optional[
        asn1crypto.x509.TbsCertificate]:
        if ct_log != self._log_url:
            return None
        leaf = self._leaf_by_hash[hash]
        return cert_encoding.get_tbs_certificate_from_leaf_bytes(leaf)

    def set_log_url(self, log_url: str):
        self._log_url = log_url

    def add_leaf(self, leaf: bytes, hash: str):
        self._leaf_by_hash[hash] = leaf


class StubCtLog:
    def __init__(self, ct_log_list: StubCtLogList, crt_sh: StubCrtSh):
        server_address = ('127.0.0.1', 0)
        self._httpd = http.server.HTTPServer(server_address, functools.partial(_StubCtHTTPRequestHandler, ct_log=self))
        threading.Thread(target=self._httpd.serve_forever).start()

        self._ct_log_list = ct_log_list
        ct_log_list.set_log_url("http://localhost:{}/".format(self._httpd.server_port))
        self._crt_sh = crt_sh

    def port(self):
        return self._httpd.server_port

    def submit(self, cert: bytes, issuer: bytes):
        leaves = cert_encoding.cert_to_merkle_tree_leaves(cert, issuer)
        for leaf in leaves:
            if leaf[0] == STUB_KEY_ID:
                leaf_hash = hashlib.sha256(b"\x00" + leaf[1]).digest()
                hash = base64.b64encode(leaf_hash).decode('utf-8')
                self._ct_log_list.add_leaf(leaf[1], hash)
                self._crt_sh.submit_cert(leaf[0], leaf_hash, cert_encoding.get_subject_cn(
                    cert_encoding.get_tbs_certificate_from_leaf_bytes(leaf[1])))

    def stop(self):
        self._httpd.shutdown()
