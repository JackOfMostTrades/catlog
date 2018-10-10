import base64
import hashlib
import json
import math
import os.path
import urllib
from typing import List, Tuple, Optional
from urllib.error import HTTPError

import asn1crypto.x509
from asn1crypto import pem

from . import ctl_parser_structures

# Each label can be 63 characters long
# The total length (including all dots) can be 253 characters.
# https://stackoverflow.com/questions/32290167/what-is-the-maximum-length-of-a-dns-name
# # Based on testing, the max DNS name length that the LE CA accepts is 230 characters
MAX_DNS_NAME_LEN = 230
MAX_DNS_LABEL_LEN = 63
MAX_SANS_PER_CERT = 100


def get_bytes_per_san(dns_suffix: str) -> int:
    num_dots = math.floor(MAX_DNS_NAME_LEN - len(dns_suffix) - 1) / MAX_DNS_LABEL_LEN
    chars_per_san = MAX_DNS_NAME_LEN - len(dns_suffix) - 1 - num_dots
    # base32 encoding has a 5/8 encoding ratio, minus 1 byte reserved as an ordinal
    bytes_per_san = math.floor(chars_per_san * 5 / 8) - 1
    return bytes_per_san


def get_bytes_per_cert(dns_suffix: str) -> int:
    return get_bytes_per_san(dns_suffix) * (MAX_SANS_PER_CERT - 1)


def data_to_domains(raw_data: bytes, dns_suffix: str) -> List[str]:
    bytes_per_san = get_bytes_per_san(dns_suffix)
    bytes_per_cert = get_bytes_per_cert(dns_suffix)

    if len(raw_data) > bytes_per_cert:
        raise Exception("Data is too big: {} > {}".format(len(raw_data), bytes_per_cert))

    sans = [dns_suffix]
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


def domains_to_data(domains: List[str], dns_suffix: str) -> bytes:
    datas = []
    for san in domains:
        if san == dns_suffix:
            continue
        if not san.endswith(dns_suffix):
            raise Exception("Unexpected SAN in cert: " + san)
        encoded = san[0:-len(dns_suffix)].replace('.', '')
        data = base64.b32decode(add_b32_padding(encoded.upper()))
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


def cert_to_leaf_hashes(certBytes: bytes, issuerCertBytes: bytes) -> List[Tuple[bytes, bytes]]:
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

    leaf_hashes = []
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
        leaf_hash = hashlib.sha256(b"\x00" + leaf).digest()
        leaf_hashes.append((sct.id, leaf_hash))
    return leaf_hashes


def get_leaf_by_hash(ct_log: str, hash: str) -> Optional[asn1crypto.x509.TbsCertificate]:
    sth = json.loads(urllib.request.urlopen("{}ct/v1/get-sth".format(ct_log)).read())
    tree_size = sth["tree_size"]
    try:
        proof = json.loads(urllib.request.urlopen(
            "{}ct/v1/get-proof-by-hash?{}".format(ct_log, urllib.parse.urlencode({
                "hash": hash,
                "tree_size": tree_size
            }))).read())
    except HTTPError as e:
        if e.code == 404:
            return None
        raise e
    leaf_index = proof["leaf_index"]
    return get_leaf_by_entry_id(ct_log, leaf_index)


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


def lookup_ct_log_by_id(log_id: bytes) -> Optional[str]:
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "all_logs_list.json"), "r") as f:
        all_logs = json.loads(f.read())
    for log in all_logs["logs"]:
        id = hashlib.sha256(base64.b64decode(log["key"])).digest()
        if id == log_id:
            return log["url"]
    return None


def lookup_ct_log_id_by_url(ct_log_url: bytes) -> Optional[str]:
    if ct_log_url.startswith("https://"):
        ct_log_url = ct_log_url[len("https://"):]
    elif ct_log_url.startswith("http://"):
        ct_log_url = ct_log_url[len("http://"):]
    if not ct_log_url.endswith('/'):
        ct_log_url += '/'

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "all_logs_list.json"), "r") as f:
        all_logs = json.loads(f.read())
    for log in all_logs["logs"]:
        if ct_log_url == log["url"]:
            return hashlib.sha256(base64.b64decode(log["key"])).digest()
    return None


def get_raw_leaf_by_entry_id(ct_log: str, entry_id: str) -> bytes:
    entries = json.loads(urllib.request.urlopen(
        "{}ct/v1/get-entries?{}".format(ct_log,
                                        urllib.parse.urlencode({
                                            "start": entry_id,
                                            "end": entry_id
                                        }))).read())
    leaf = base64.b64decode(entries["entries"][0]["leaf_input"])
    return leaf


def get_leaf_by_entry_id(ct_log: str, entry_id: str) -> asn1crypto.x509.TbsCertificate:
    leaf = get_raw_leaf_by_entry_id(ct_log, entry_id)
    leaf_cert = ctl_parser_structures.MerkleTreeLeaf.parse(leaf).TimestampedEntry

    if leaf_cert.LogEntryType == "X509LogEntryType":
        # We have a normal x509 entry
        cert = asn1crypto.x509.Certificate.load(leaf_cert.Entry.CertData)
        tbsCert = cert["tbs_certificate"]
    else:
        # We have a precert entry
        tbsCert = asn1crypto.x509.TbsCertificate.load(leaf_cert.Entry.TBSCertificate)

    return tbsCert