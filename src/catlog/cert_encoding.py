import base64
import hashlib
import io
import json
import math
import os.path
import urllib
from typing import List, Tuple, Optional
from urllib.error import HTTPError

import asn1crypto.x509
from asn1crypto import pem

from . import ctl_parser_structures

# The total length (including all dots) of a DNS name can be is 253 characters. However, the max that LE
# supports is 230 characters:
# https://github.com/letsencrypt/boulder/blob/93ac7fbe9e77b190c5c6496b4e9d765775588963/policy/pa.go#L163
MAX_DNS_NAME_LEN = 230
# Max label length is 63 characters according to RFC and this enforced by LE:
# https://github.com/letsencrypt/boulder/blob/93ac7fbe9e77b190c5c6496b4e9d765775588963/policy/pa.go#L162
MAX_DNS_LABEL_LEN = 63
# https://letsencrypt.org/docs/rate-limits/
MAX_SANS_PER_CERT = 100


def get_bytes_per_san(dns_suffix: str) -> int:
    num_dots = math.floor(MAX_DNS_NAME_LEN - len(dns_suffix) - 1) / MAX_DNS_LABEL_LEN
    chars_per_san = MAX_DNS_NAME_LEN - len(dns_suffix) - 1 - num_dots
    # base32 encoding has a 5/8 encoding ratio, minus 1 byte reserved as an ordinal
    bytes_per_san = math.floor(chars_per_san * 5 / 8) - 1
    return bytes_per_san


def get_bytes_per_cert(dns_suffix: str) -> int:
    return get_bytes_per_san(dns_suffix) * (MAX_SANS_PER_CERT - 1)


def data_to_domains(raw_data: bytes, common_name: str, dns_suffix: str) -> List[str]:
    if not common_name.endswith(dns_suffix):
        raise Exception("Common name must end with dns_suffix")

    bytes_per_san = get_bytes_per_san(dns_suffix)
    bytes_per_cert = get_bytes_per_cert(dns_suffix)

    if len(raw_data) > bytes_per_cert:
        raise Exception("Data is too big: {} > {}".format(len(raw_data), bytes_per_cert))

    sans = [common_name]
    data = raw_data
    index = 0
    while len(data) > 0:
        chunk = base64.b32encode(bytes([index]) + data[0:bytes_per_san]).decode('utf-8').rstrip("=")
        index += 1
        san = '.'.join(
            [chunk[i:i + MAX_DNS_LABEL_LEN] for i in range(0, len(chunk), MAX_DNS_LABEL_LEN)]) + '.' + dns_suffix
        sans.append(san)
        data = data[bytes_per_san:]
    return sans


def add_b32_padding(d: str) -> str:
    padding = "=" * ((8 - (len(d) % 8)) % 8)
    return d + padding


def find_dns_suffix(domains: List[str]) -> str:
    suffix = domains[0].split('.')
    for i in range(1, len(domains)):
        domain = domains[i].split('.')
        for j in range(len(suffix)):
            if domain[len(domain) - j - 1] != suffix[len(suffix) - j - 1]:
                suffix = suffix[len(suffix) - j:]
                break
    return '.'.join(suffix)


def domains_to_data(domains: List[str], common_name: str) -> bytes:
    dns_suffix = find_dns_suffix(domains)
    datas = []
    for san in domains:
        if san == common_name:
            continue
        if not san.endswith(dns_suffix):
            raise Exception("Unexpected SAN in cert: " + san)
        encoded = san[0:-len(dns_suffix)].replace('.', '')
        data = base64.b32decode(add_b32_padding(encoded.upper()))
        if len(data) < 2:
            raise Exception("Unable to decode data from SAN: {}".format(san))
        datas.append({"ordinal": data[0], "data": data[1:]})
    datas.sort(key=lambda x: x["ordinal"])
    result = bytes()
    for data in datas:
        result += data["data"]
    return result


def pem_to_der(cert: str) -> bytes:
    if not pem.detect(cert):
        raise Exception("Unable to parse PEM: " + cert)
    _, _, der_bytes = pem.unarmor(cert)
    return der_bytes


def cert_to_merkle_tree_leaves(certBytes: bytes, issuerCertBytes: bytes) -> List[Tuple[bytes, bytes]]:
    issuer = asn1crypto.x509.Certificate.load(issuerCertBytes)
    cert = asn1crypto.x509.Certificate.load(certBytes)

    issuer_key_hash = hashlib.sha256(issuer["tbs_certificate"]["subject_public_key_info"].dump()).digest()
    tbsCert = cert["tbs_certificate"]
    scts = []
    for i in range(len(tbsCert["extensions"])):
        if tbsCert["extensions"][i]["extn_id"].native == "signed_certificate_timestamp_list":
            # Parse log id, timestamp, extensions out of extension
            sct_list = ctl_parser_structures.SignedCertificateTimestampList.parse(
                tbsCert["extensions"][i]["extn_value"].parsed.native)
            for sct in sct_list.sct_list:
                scts.append(sct.sct)
            del tbsCert["extensions"][i]
            break

    tbsCertBytes = tbsCert.dump()

    leaves = []
    for sct in scts:
        leaf = ctl_parser_structures.MerkleTreeLeaf.build(dict(
            Version=0,
            MerkleLeafType=0,
            TimestampedEntry=dict(
                Timestamp=sct.timestamp,
                LogEntryType="PrecertLogEntryType",
                Entry=dict(
                    IssuerKeyHash=issuer_key_hash,
                    TBSCertificateLength=len(tbsCertBytes),
                    TBSCertificate=tbsCertBytes
                ),
                Extensions=sct.extensions
            )
        ))
        leaves.append((sct.id, leaf))
    return leaves

def cert_to_leaf_hashes(certBytes: bytes, issuerCertBytes: bytes) -> List[Tuple[bytes, bytes]]:
    leaves = cert_to_merkle_tree_leaves(certBytes, issuerCertBytes)
    leaf_hashes = []
    for leaf in leaves:
        leaf_hash = hashlib.sha256(b"\x00" + leaf[1]).digest()
        leaf_hashes.append((leaf[0], leaf_hash))
    return leaf_hashes


def get_subject_cn(tbsCert: asn1crypto.x509.TbsCertificate):
    return tbsCert["subject"].native["common_name"]


def get_sans(tbsCert: asn1crypto.x509.TbsCertificate):
    sans = []
    for ext in tbsCert["extensions"]:
        if ext["extn_id"].native == "subject_alt_name":
            for general_name in ext["extn_value"].parsed:
                if isinstance(general_name.chosen, asn1crypto.x509.DNSName):
                    sans.append(general_name.chosen.native)
    return sans


class CtLogList:
    def __init__(self):
        self._sth_cache = {}
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "all_logs_list.json"), "r") as f:
            self._all_logs = json.loads(f.read())

    def lookup_ct_log_by_id(self, log_id: bytes) -> Optional[str]:
        for log in self._all_logs["logs"]:
            id = hashlib.sha256(base64.b64decode(log["key"])).digest()
            if id == log_id:
                return log["url"]
        return None

    def lookup_ct_log_id_by_url(self, ct_log_url: str) -> Optional[bytes]:
        if ct_log_url.startswith("https://"):
            ct_log_url = ct_log_url[len("https://"):]
        elif ct_log_url.startswith("http://"):
            ct_log_url = ct_log_url[len("http://"):]
        if not ct_log_url.endswith('/'):
            ct_log_url += '/'

        for log in self._all_logs["logs"]:
            if ct_log_url == log["url"]:
                return hashlib.sha256(base64.b64decode(log["key"])).digest()
        return None

    def get_sth(self, ct_log, debug_file: io.IOBase = None):
        if ct_log in self._sth_cache:
            return self._sth_cache[ct_log]

        url = "{}ct/v1/get-sth".format(ct_log)
        if debug_file is not None:
            print("Fetching {}".format(url), file=debug_file)
        sth = json.loads(urllib.request.urlopen(url).read())
        self._sth_cache[ct_log] = sth
        return sth

    def get_leaf_by_hash(self, ct_log: str, hash: str, debug_file: io.IOBase = None) -> Optional[
        asn1crypto.x509.TbsCertificate]:
        if (not ct_log.startswith("http://")) and (not ct_log.startswith("https://")):
            ct_log = "https://" + ct_log

        sth = self.get_sth(ct_log, debug_file=debug_file)

        tree_size = sth["tree_size"]
        try:
            url = "{}ct/v1/get-proof-by-hash?{}".format(ct_log, urllib.parse.urlencode({
                "hash": hash,
                "tree_size": tree_size
            }))

            if debug_file is not None:
                print("Fetching {}".format(url), file=debug_file)

            proof = json.loads(urllib.request.urlopen(url).read())
        except HTTPError as e:
            if e.code == 404:
                return None
            raise e
        leaf_index = proof["leaf_index"]
        return get_leaf_by_entry_id(ct_log, leaf_index, debug_file=debug_file)


def get_raw_leaf_by_entry_id(ct_log: str, entry_id: int, debug_file: io.IOBase = None) -> bytes:
    url = "{}ct/v1/get-entries?{}".format(ct_log,
                                          urllib.parse.urlencode({
                                            "start": str(entry_id),
                                            "end": str(entry_id)
                                          }))
    if debug_file is not None:
        print("Fetching {}".format(url), file=debug_file)

    entries = json.loads(urllib.request.urlopen(url).read())
    leaf = base64.b64decode(entries["entries"][0]["leaf_input"])
    return leaf


def get_leaf_by_entry_id(ct_log: str, entry_id: int, debug_file: io.IOBase = None) -> asn1crypto.x509.TbsCertificate:
    if (not ct_log.startswith("http://")) and (not ct_log.startswith("https://")):
        ct_log = "https://" + ct_log

    leaf = get_raw_leaf_by_entry_id(ct_log, entry_id, debug_file=debug_file)
    return get_tbs_certificate_from_leaf_bytes(leaf)


def get_tbs_certificate_from_leaf_bytes(leaf: bytes) -> asn1crypto.x509.TbsCertificate:
    leaf_cert = ctl_parser_structures.MerkleTreeLeaf.parse(leaf).TimestampedEntry

    if leaf_cert.LogEntryType == "X509LogEntryType":
        # We have a normal x509 entry
        cert = asn1crypto.x509.Certificate.load(leaf_cert.Entry.CertData)
        tbsCert = cert["tbs_certificate"]
    else:
        # We have a precert entry
        tbsCert = asn1crypto.x509.TbsCertificate.load(leaf_cert.Entry.TBSCertificate)

    return tbsCert