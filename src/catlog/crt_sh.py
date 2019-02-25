import hashlib
import json
import re
import urllib.parse
import urllib.request
from typing import List, Tuple

from . import cert_encoding


class CrtSh:

    def __init__(self, ct_log_list: cert_encoding.CtLogList = None):
        self._ct_log_list = ct_log_list

    def get_cert_ids_by_cn(self, common_name: str) -> List[str]:
        response_body = urllib.request.urlopen(
            "https://crt.sh/?{}".format(urllib.parse.urlencode({
                "CN": common_name,
                "output": "json"
            }))).read()
        results = json.JSONDecoder().decode(response_body.decode('utf-8'))
        ids = []
        for obj in results:
            ids.append(obj["min_cert_id"])
        return ids

    def get_leaf_hashes_by_cert_id(self, cert_id: str) -> List[Tuple[bytes, bytes]]:
        # Alas, crt.sh doesn't support JSON format for fetching full cert data. So let's do some HTML scraping...
        response_body = urllib.request.urlopen(
            "https://crt.sh/?{}".format(urllib.parse.urlencode({
                "id": cert_id
            }))).read().decode('utf-8')

        entry_ids = []
        for match in re.finditer(
                r'<TABLE class="options" style="margin-left:0px">\s*<TR>\s*<TH>Timestamp</TH>\s*<TH>Entry #</TH>\s*<TH>Log Operator</TH>\s*<TH>Log URL</TH>\s*</TR>\s*(.*?)\s*</TABLE>',
                response_body, re.DOTALL):
            rows = match.group(1)
            for row_match in re.finditer(
                    "\s*<TR>\s*<TD>(.*?)</TD>\s*<TD>(.*?)</TD>\s*<TD>(.*?)</TD>\s*<TD>(.*?)</TD>\s*</TR>\s*", rows):
                ct_log_url = row_match.group(4)
                ct_log_entry_id = row_match.group(2)
                entry_ids.append((ct_log_url, ct_log_entry_id))

        # We could use the entry IDs directly, but there's a lot of code which operates on the basis of leaf hashes. So lookup
        # each entry and convert it back into a leaf hash
        leaf_hashes = []
        for entry_id in entry_ids:
            ct_log_url = entry_id[0]
            if not ct_log_url.endswith('/'):
                ct_log_url += '/'
            log_id = self._ct_log_list.lookup_ct_log_id_by_url(ct_log_url)
            if log_id is not None:
                leaf = cert_encoding.get_raw_leaf_by_entry_id(ct_log_url, entry_id[1])
                leaf_hash = hashlib.sha256(b"\x00" + leaf).digest()
                leaf_hashes.append((log_id, leaf_hash))

        return leaf_hashes
