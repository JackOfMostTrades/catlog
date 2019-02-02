from typing import List, Tuple

from catlog import crt_sh


class StubCrtSh(crt_sh.CrtSh):

    def __init__(self):
        self._id_to_cert = {}
        self._cn_to_ids = {}

    def get_cert_ids_by_cn(self, common_name: str) -> List[str]:
        if common_name not in self._cn_to_ids:
            return []
        return self._cn_to_ids[common_name]

    def get_leaf_hashes_by_cert_id(self, cert_id: str) -> List[Tuple[bytes, bytes]]:
        if cert_id not in self._id_to_cert:
            return []
        return [self._id_to_cert[cert_id]]

    def submit_cert(self, log_id: bytes, leaf_hash: bytes, common_name: str):
        id = str(len(self._id_to_cert))
        if common_name in self._cn_to_ids:
            self._cn_to_ids[common_name].append(id)
        else:
            self._cn_to_ids[common_name] = [id]
        self._id_to_cert[id] = (log_id, leaf_hash)
