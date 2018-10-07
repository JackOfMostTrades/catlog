import base64
import hashlib
import json
import os.path
import sys
import urllib.request

import asn1crypto.core
import asn1crypto.x509

from . import ctl_parser_structures


def get_leaf_by_entry_id(ct_log, entry_id):
    entries = json.loads(urllib.request.urlopen(
        "{}/ct/v1/get-entries?start={}&end={}".format(ct_log, entry_id, entry_id)).read())
    leaf = base64.b64decode(entries["entries"][0]["leaf_input"])

    leaf_cert = ctl_parser_structures.MerkleTreeLeaf.parse(leaf).TimestampedEntry

    if leaf_cert.LogEntryType == "X509LogEntryType":
        # We have a normal x509 entry
        cert = asn1crypto.x509.Certificate.load(leaf_cert.Entry.CertData)
        tbsCert = cert["tbs_certificate"]
    else:
        # We have a precert entry
        tbsCert = asn1crypto.x509.TbsCertificate.load(leaf_cert.Entry.TBSCertificate)

    return tbsCert

def get_leaf_by_hash(ct_log, hash):
    sth = json.loads(urllib.request.urlopen("{}/ct/v1/get-sth".format(ct_log)).read())
    tree_size = sth["tree_size"]
    try:
        proof = json.loads(urllib.request.urlopen(
            "{}/ct/v1/get-proof-by-hash?hash={}&tree_size={}".format(ct_log, hash, tree_size)).read())
    except:
        return None
    leaf_index = proof["leaf_index"]
    return get_leaf_by_entry_id(ct_log, leaf_index)

def get_subject_cn(tbsCert):
    return tbsCert["subject"].native["common_name"]

def get_sans(tbsCert):
    sans = []
    for ext in tbsCert["extensions"]:
        if ext["extn_id"].native == "subject_alt_name":
            for general_name in ext["extn_value"].parsed:
                if isinstance(general_name.chosen, asn1crypto.x509.DNSName):
                    sans.append(general_name.chosen.native)
    return sans

def cert_to_leaf_hashes(certBytes, issuerCertBytes):
    issuer = asn1crypto.x509.Certificate.load(issuerCertBytes)
    cert = asn1crypto.x509.Certificate.load(certBytes)

    issuer_key_hash = hashlib.sha256(issuer["tbs_certificate"]["subject_public_key_info"].dump()).digest()
    tbsCert = cert["tbs_certificate"]
    scts = []
    for i in range(len(tbsCert["extensions"])):
        if tbsCert["extensions"][i]["extn_id"].native == "signed_certificate_timestamp_list":
            # Parse log id, timestamp, extensions out of extension
            sct_list = ctl_parser_structures.SignedCertificateTimestampList.parse(tbsCert["extensions"][i]["extn_value"].parsed.native)
            for sct in sct_list.sct_list:
                scts.append(sct.sct)
            del tbsCert["extensions"][i]
            break

    tbsCertBytes = tbsCert.dump()
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
        leaf_hash = base64.b64encode(hashlib.sha256(b"\x00" + leaf).digest()).decode('utf-8')
        print("log_id={}, leaf_hash={}".format(sct.id.hex(), leaf_hash))

def push(cliArgs):
    if len(cliArgs) != 1:
        raise Exception("catlog push expects exactly one argument")
    path = cliArgs[0]
    if not os.path.isfile(path):
        raise Exception("File not found: " + path)
    with open(path, "rb") as f:
        file_data = f.read()
    push_data(f)


def push_data(data):
    tbsCert = get_leaf_by_hash("https://ct.googleapis.com/icarus", "0Jw8rUAEGgbFuTb196OBfbjAPGlW80KupXV4idizeFA=")
    #tbsCert = print(get_leaf_by_hash( "https://ct.googleapis.com/logs/argon2018", "IFiyQRhyGeLTKvDp9t8RUSf2Dv5KT1DX1XR6Mx0sMXU="))

    print(get_subject_cn(tbsCert))
    print(get_sans(tbsCert))

    cert_to_leaf_hashes(open("/home/ihaken/Downloads/leaf.crt", "rb").read(),
                        open("/home/ihaken/Downloads/issuer.crt", "rb").read())


def main(args):
    if args[0] == 'push':
        push(args[1:])
    else:
        raise Exception("Unsupported subcommand: " + args[0])

if __name__ == "__main__":
    main(sys.argv[1:])
