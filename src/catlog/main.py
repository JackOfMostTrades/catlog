import base64
import hashlib
import os.path
import sys

from . import catlog_pb2
from . import cert_encoding
from . import le_client
from .catlog_db import CatlogDb


def push(cliArgs):
    if len(cliArgs) != 1:
        raise Exception("catlog push expects exactly one argument")
    path = cliArgs[0]
    if not os.path.isfile(path):
        raise Exception("File not found: " + path)
    with open(path, "rb") as f:
        file_data = f.read()
    push_data(file_data)


def push_data(data: bytes) -> None:
    catlog_db = CatlogDb()

    client = le_client.LeClient(catlog_db)
    previous_chunk_ref = None
    while len(data) > 0:
        domain = catlog_db.pick_domain(True)
        bytes_per_cert = cert_encoding.get_bytes_per_cert(domain.domain)

        # Figure out how big to make this cert's chunk...
        chunk_size = bytes_per_cert
        chunk_data = None
        while chunk_size > 0:
            chunk = catlog_pb2.CertificateData(
                data_chunk=catlog_pb2.DataChunk(
                    previous_chunk=previous_chunk_ref,
                    chunk=data[:chunk_size]
                )
            )
            chunk_data = bytes(chunk.SerializeToString())
            if len(chunk_data) <= bytes_per_cert:
                break
            chunk_size -= 1

        # Actually mint the cert...
        cert, issuer = client.mint_cert(domain, chunk_data)

        # Build the previous chunk reference...
        leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
        log_entry_refs = []
        for leaf_hash in leaf_hashes:
            log_entry_refs.append(catlog_pb2.LogEntryReference(
                log_id=leaf_hash[0],
                leaf_hash=leaf_hash[1]
            ))
        previous_chunk_ref = catlog_pb2.CertificateReference(
            fingerprint_sha256=hashlib.sha256(cert).digest(),
            log_entry=log_entry_refs
        )

        data = data[chunk_size:]

    return previous_chunk_ref


def pull_data(ct_log_id: bytes, leaf_hash: bytes) -> bytes:
    previous_chunk_ref = catlog_pb2.CertificateReference(
        log_entry=[catlog_pb2.LogEntryReference(
            log_id=ct_log_id,
            leaf_hash=leaf_hash
        )]
    )
    data = bytes()
    while previous_chunk_ref is not None:
        log_entry = previous_chunk_ref.log_entry[0]
        ct_log_id = log_entry.log_id
        leaf_hash = log_entry.leaf_hash
        ct_log_url = cert_encoding.lookup_ct_log_by_id(ct_log_id)
        tbsCert = cert_encoding.get_leaf_by_hash("https://" + ct_log_url, base64.b64encode(leaf_hash).decode('utf-8'))
        encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert),
                                                cert_encoding.get_subject_cn(tbsCert))
        data_chunk = catlog_pb2.CertificateData.ParseFromString(encoded).data_chunk
        previous_chunk_ref = data_chunk.previous_chunk
        data = data_chunk.chunk + data

    return data

def main(args):
    if args[0] == 'push':
        push(args[1:])
    else:
        raise Exception("Unsupported subcommand: " + args[0])

if __name__ == "__main__":
    main(sys.argv[1:])
