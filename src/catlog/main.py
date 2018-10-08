import base64
import hashlib
import os
import os.path
import sys
from typing import List, Optional, Tuple

from . import catlog_pb2
from . import cert_encoding
from . import le_client
from .bucket_db import discover_bucket_root, BucketDb, FileStatus
from .catlog_db import CatlogDb
from .config_cmd import config_cmd


def init(cliArgs):
    if len(cliArgs) != 0:
        raise Exception("catlog init doesn't take arguments")
    bucket_root = discover_bucket_root()
    if bucket_root is not None:
        raise Exception("It looks like you're already working under a bucket: " + bucket_root)
    bucket_root = os.path.join(os.getcwd(), ".catlog")
    if not os.path.isdir(bucket_root):
        os.mkdir(bucket_root, 0o700)
    # Instantiate an empty bucket db
    bucket_db = BucketDb(bucket_root)
    bucket_db.close()


def push(cliArgs):
    if len(cliArgs) != 1:
        raise Exception("catlog push expects exactly one argument")
    path = cliArgs[0]
    if not os.path.isfile(path):
        raise Exception("File not found: " + path)

    # Manage the file status using the bucket db
    bucket_root = discover_bucket_root()
    if bucket_root is None:
        raise Exception("Must be working in a bucket to push files. Perhaps you need to run `catlog init`?")
    bucket_db = BucketDb(bucket_root)
    try:
        relpath = os.path.relpath(path, bucket_root)
        file_status = bucket_db.get_file_status(relpath)
        if file_status is None:
            file_status = FileStatus(filename=relpath)

        with open(path, "rb") as f:
            file_data = f.read()
        push_data(file_data, bucket_db, file_status)
    finally:
        bucket_db.close()


def commit(cliArgs):
    if len(cliArgs) != 0:
        raise Exception("catlog commit doesn't take any arguments")

    bucket_root = discover_bucket_root()
    if bucket_root is None:
        raise Exception("No bucket found. `catlog commit` can only be run from within a bucket!")
    bucket_db = BucketDb(bucket_root)
    catlog_db = CatlogDb()
    try:
        files_to_commit = bucket_db.get_all_files_for_commit()
        if len(files_to_commit) == 0:
            print("Up to date!")
            return
        print("Committing {} new files...".format(len(files_to_commit)))

        file_data = []
        for file_status in files_to_commit:
            log_refs = []
            for leaf_hash in file_status.log_entries:
                log_refs.append(catlog_pb2.LogEntryReference(
                    log_id=leaf_hash[0],
                    leaf_hash=leaf_hash[1]
                ))
            file_data.append(catlog_pb2.CertificateReference(
                fingerprint_sha256=file_status.upload_fingerprint_sha256,
                log_entry=log_refs
            ))

        client = le_client.LeClient(catlog_db)
        previous_chunk_ref = None

        fingerprint_sha256 = bucket_db.get_bucket_fingerprint_sha256()
        leaf_hashes = bucket_db.get_bucket_refs()
        if (fingerprint_sha256 is not None) or len(leaf_hashes) > 0:
            log_entry_refs = []
            for leaf_hash in leaf_hashes:
                log_entry_refs.append(catlog_pb2.LogEntryReference(
                    log_id=leaf_hash[0],
                    leaf_hash=leaf_hash[1]
                ))
            previous_chunk_ref = catlog_pb2.CertificateReference(
                fingerprint_sha256=fingerprint_sha256,
                log_entry=log_entry_refs
            )

        while len(file_data) > 0:
            domain = catlog_db.pick_domain(True)
            bytes_per_cert = cert_encoding.get_bytes_per_cert(domain.domain)

            # Figure out how big to make this cert's chunk...
            num_files = len(file_data)
            chunk_data = None
            while num_files > 0:
                chunk = catlog_pb2.CertificateData(
                    box_chunk=catlog_pb2.BoxChunk(
                        previous_chunk=previous_chunk_ref,
                        file_data=file_data[:num_files]
                    )
                )
                chunk_data = bytes(chunk.SerializeToString())
                if len(chunk_data) <= bytes_per_cert:
                    break
                num_files -= 1
            if num_files == 0:
                raise Exception("Unable to find any acceptable encoding size!")

            # Actually mint the cert...
            print("Minting a certificate that commits {} new files to the bucket...".format(num_files))
            cert, issuer = client.mint_cert(domain, chunk_data)

            # Build the previous chunk reference...
            leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
            log_entry_refs = []
            for leaf_hash in leaf_hashes:
                log_entry_refs.append(catlog_pb2.LogEntryReference(
                    log_id=leaf_hash[0],
                    leaf_hash=leaf_hash[1]
                ))
            fingerprint_sha256 = hashlib.sha256(cert).digest()
            previous_chunk_ref = catlog_pb2.CertificateReference(
                fingerprint_sha256=fingerprint_sha256,
                log_entry=log_entry_refs
            )

            # Update the bucket_db, marking the new bucket refs and committed files
            bucket_db.mark_files_committed([x.name for x in file_data[:num_files]])
            bucket_db.set_bucket_refs(fingerprint_sha256, leaf_hashes)

            # Finally, reset file_data for next iteration
            file_data = file_data[num_files:]

        return None
    finally:
        catlog_db.close()
        bucket_db.close()


def clone(cliArgs):
    if len(cliArgs) != 1:
        raise Exception("Expected exactly only argument to `catlog clone`")
    log_entry = parse_log_ref(cliArgs[0])
    if log_entry is None:
        raise Exception("`catlog clone` argument not a valid log reference: " + cliArgs[0])

    bucket_root = discover_bucket_root()
    if bucket_root is not None:
        raise Exception(
            "Already inside a bucket. `catlog clone` should be issued inside a directory you intend to use as the cloned bucket")
    bucket_root = os.path.join(os.getcwd(), ".catlog")
    if not os.path.isdir(bucket_root):
        os.mkdir(bucket_root, 0o700)

    bucket_db = BucketDb(bucket_root)
    try:
        previous_chunk_ref = catlog_pb2.CertificateReference(
            log_entry=[(
                catlog_pb2.LogEntryReference(
                    log_id=log_entry[0],
                    leaf_hash=log_entry[1]
                )
            )])

        while previous_chunk_ref is not None and len(previous_chunk_ref.log_entry) > 0:
            ct_log_url = None
            for log_entry in previous_chunk_ref.log_entry:
                ct_log_id = log_entry.log_id
                leaf_hash = log_entry.leaf_hash
                ct_log_url = cert_encoding.lookup_ct_log_by_id(ct_log_id)
                if ct_log_url is not None:
                    break

            if ct_log_url is None:
                raise Exception("Unable to resolve any CT logs from log IDs")

            tbsCert = cert_encoding.get_leaf_by_hash("https://" + ct_log_url,
                                                     base64.b64encode(leaf_hash).decode('utf-8'))
            encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert),
                                                    cert_encoding.get_subject_cn(tbsCert))
            cert_data = catlog_pb2.CertificateData()
            cert_data.ParseFromString(encoded)
            box_chunk = cert_data.box_chunk
            previous_chunk_ref = box_chunk.previous_chunk
            for file_datum in box_chunk.file_data:
                file_status = FileStatus(filename=file_datum.name)
                file_status.upload_complete = True
                file_status.upload_fingerprint_sha256 = file_datum.certificate_reference.fingerprint_sha256
                file_status.committed = True
                for log_entry in file_datum.certificate_reference.log_entry:
                    file_status.log_entries.append((
                        log_entry.log_id, log_entry.leaf_hash
                    ))
                bucket_db.set_file_status(file_status)
    finally:
        bucket_db.close()


def status(cliArgs):
    if len(cliArgs) != 0:
        raise Exception("No arguments supported for catlog status command.")

    bucket_root = discover_bucket_root()
    if bucket_root is None:
        raise Exception("Bucket not found. Perhaps you need to run `catlog init`?")
    bucket_db = BucketDb(bucket_root)
    try:
        not_fetched = []
        fetched = []
        uncommitted = []
        partially_uploaded = []
        for file in bucket_db.get_all_files():
            full_path = os.path.join(bucket_root, file.filename)
            if not file.upload_complete:
                partially_uploaded.append(file)
            elif not file.committed:
                uncommitted.append(file)
            elif not os.path.exists(full_path):
                not_fetched.append(file)
            else:
                fetched.append(file)

        if len(partially_uploaded) > 0:
            print("Partially upload...")
            print("-------------------")
            for file in partially_uploaded:
                print(file.filename)
            print()
        if len(uncommitted) > 0:
            print("Uploaded but uncommitted...")
            print("---------------------------")
            for file in uncommitted:
                print(file.filename)
            print()
        if len(not_fetched) > 0:
            print("Available but not fetched...")
            print("----------------------------")
            for file in not_fetched:
                print(file.filename)

        # FIXME: We should look for and report on files under the bucket_root that are completely untracked.
    finally:
        bucket_db.close()


def config(cliArgs):
    config_cmd(cliArgs)


def push_data(data: bytes, bucket_db: Optional[BucketDb], file_status: Optional[FileStatus]) -> None:
    catlog_db = CatlogDb()
    client = le_client.LeClient(catlog_db)
    previous_chunk_ref = None

    if (file_status is not None) and (file_status.upload_offset > 0) and (
            file_status.upload_fingerprint_sha256 is not None) and (len(file_status.log_entries) > 0):
        print("Attempting to push {} bytes of data, starting at previously uploaded offset of {}...", len(data),
              file_status.upload_offset)

        data = data[file_status.upload_offset:]
        log_entry_refs = []
        for leaf_hash in file_status.log_entries:
            log_entry_refs.append(catlog_pb2.LogEntryReference(
                log_id=leaf_hash[0],
                leaf_hash=leaf_hash[1]
            ))
        previous_chunk_ref = catlog_pb2.CertificateReference(
            fingerprint_sha256=file_status.upload_fingerprint_sha256,
            log_entry=log_entry_refs
        )
    else:
        print("Attempting to push {} bytes of data...".format(len(data)))

    while len(data) > 0:
        domain = catlog_db.pick_domain(True)
        bytes_per_cert = cert_encoding.get_bytes_per_cert(domain.domain)

        # Figure out how big to make this cert's chunk...
        chunk_size = min(bytes_per_cert, len(data))
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
        if chunk_size == 0:
            raise Exception("Unable to find any acceptable encoding size!")

        # Actually mint the cert...
        print("Minting a certificate that commits {} bytes of data...".format(chunk_size))
        cert, issuer = client.mint_cert(domain, chunk_data)

        # Build the previous chunk reference...
        leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
        log_entry_refs = []
        for leaf_hash in leaf_hashes:
            log_entry_refs.append(catlog_pb2.LogEntryReference(
                log_id=leaf_hash[0],
                leaf_hash=leaf_hash[1]
            ))
        fingerprint_sha256 = hashlib.sha256(cert).digest()
        previous_chunk_ref = catlog_pb2.CertificateReference(
            fingerprint_sha256=fingerprint_sha256,
            log_entry=log_entry_refs
        )

        # Update the bucket_db if working inside a bucket
        if (bucket_db is not None) and (file_status is not None):
            new_file_status = FileStatus(id=file_status.id, filename=file_status.filename)
            new_file_status.upload_offset = file_status.upload_offset + chunk_size
            new_file_status.upload_complete = (len(data) <= chunk_size)
            new_file_status.upload_fingerprint_sha256 = fingerprint_sha256
            new_file_status.committed = file_status.committed
            new_file_status.log_entries = leaf_hashes
            bucket_db.set_file_status(new_file_status)
            file_status = new_file_status

        data = data[chunk_size:]

    return previous_chunk_ref


def parse_log_ref(s: str) -> Optional[Tuple[bytes, bytes]]:
    if (len(s) == 89) and s[44] == '|':
        return (
            base64.b64decode(s[:44]),
            base64.b64decode(s[45:])
        )
    return None


def pull(cliArgs):
    if len(cliArgs) != 1:
        raise Exception("catlog pull expects exactly one argument")
    filename_arg = cliArgs[0]
    log_entry_arg = parse_log_ref(filename_arg)
    if log_entry_arg is not None:
        log_entries = [log_entry_arg]
        output_target = None
    else:
        # Assume this is an actual file path.
        full_path = os.path.abspath(cliArgs[0])
        if os.path.exists(full_path):
            raise Exception("Destination filename already exists: " + full_path)
        bucket_root = discover_bucket_root()
        if bucket_root is None:
            raise Exception("Not working in a bucket; cannot pull file by path name.")
        rel_path = os.path.relpath(full_path, bucket_root)
        bucket_db = BucketDb(bucket_root)
        file_status = bucket_db.get_file_status(rel_path)
        bucket_db.close()
        if file_status is None:
            raise Exception("File path {} is unknown to bucket.".format(rel_path))

        log_entries = file_status.log_entries
        output_target = full_path

    data = pull_data(log_entries)

    if output_target is None:
        os.write(1, data)  # FIXME: Is there a python constant for stdout?
    else:
        d = os.path.dirname(output_target)
        if not os.path.isdir(d):
            os.mkdir(d)
        with open(output_target, "wb") as f:
            f.write(data)


def pull_data(log_entries: List[Tuple[bytes, bytes]]) -> bytes:
    previous_chunk_ref = catlog_pb2.CertificateReference()
    for log_entry in log_entries:
        ref = previous_chunk_ref.log_entry.add()
        ref.log_id = log_entry[0]
        ref.leaf_hash = log_entry[1]

    data = bytes()
    while previous_chunk_ref is not None and len(previous_chunk_ref.log_entry) > 0:
        ct_log_url = None
        for log_entry in previous_chunk_ref.log_entry:
            ct_log_id = log_entry.log_id
            leaf_hash = log_entry.leaf_hash
            ct_log_url = cert_encoding.lookup_ct_log_by_id(ct_log_id)
            if ct_log_url is not None:
                break

        if ct_log_url is None:
            raise Exception("Unable to resolve any CT logs from log IDs")

        tbsCert = cert_encoding.get_leaf_by_hash("https://" + ct_log_url, base64.b64encode(leaf_hash).decode('utf-8'))
        encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert),
                                                cert_encoding.get_subject_cn(tbsCert))
        cert_data = catlog_pb2.CertificateData()
        cert_data.ParseFromString(encoded)
        data_chunk = cert_data.data_chunk
        previous_chunk_ref = data_chunk.previous_chunk
        data = data_chunk.chunk + data

    return data


def add(cliArgs):
    if len(cliArgs) != 2:
        raise Exception("catlog add command expects exactly two arguments")
    filename = cliArgs[0]
    log_ref = parse_log_ref(cliArgs[1])
    if log_ref is None:
        raise Exception("Second argument to `catlog add` must be a log ref: " + cliArgs[1])

    bucket_root = discover_bucket_root()
    if bucket_root is None:
        raise Exception("`catlog add` can only be run in a bucket!")
    bucket_db = BucketDb(bucket_root)

    try:
        # Sanity check that the ref is something we can fetch
        ct_log_url = cert_encoding.lookup_ct_log_by_id(log_ref[0])
        if ct_log_url is None:
            raise Exception("Unable to resolve CT log from log ID")
        tbsCert = cert_encoding.get_leaf_by_hash(ct_log_url, base64.b64encode(log_ref[1]).decode('utf-8'))
        if tbsCert is None:
            raise Exception("Unable to lookup log ref: " + cliArgs[1])

        # Add uploaded but uncommitted status for the filename to the bucket
        file_status = FileStatus(filename=filename)
        file_status.upload_complete = True
        file_status.committed = False
        file_status.log_entries = [log_ref]

        bucket_db.set_file_status(file_status)
    finally:
        bucket_db.close()


def main(args):
    if args[0] == 'push':
        push(args[1:])
    elif args[0] == 'init':
        init(args[1:])
    elif args[0] == 'pull':
        pull(args[1:])
    elif args[0] == 'config':
        config(args[1:])
    elif args[0] == 'status':
        status(args[1:])
    elif args[0] == 'clone':
        clone(args[1:])
    elif args[0] == 'commit':
        commit(args[1:])
    elif args[0] == 'add':
        add(args[1:])
    else:
        raise Exception("Unsupported subcommand: " + args[0])

if __name__ == "__main__":
    main(sys.argv[1:])
