import base64
import hashlib
import os
import os.path
import re
import sys
from typing import List, Optional

from . import catlog_pb2
from . import cert_encoding
from . import crt_sh
from . import le_client
from .box_db import discover_box_root, BoxDb, FileStatus
from .catlog_db import CatlogDb
from .config_cmd import config_cmd


class CatlogMain:
    def __init__(self):
        self._catlog_db = CatlogDb()
        box_root = discover_box_root()
        if box_root is not None:
            self._box_root = box_root
            self._box_db = BoxDb(box_root)
        else:
            self._box_root = None
            self._box_db = None
        self._le_client = le_client.LeClient(False, self._catlog_db)
        self._ct_log_list = cert_encoding.CtLogList()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self._catlog_db.close()
        if self._box_db is not None:
            self._box_db.close()

    def init(self, cliArgs):
        if len(cliArgs) != 1:
            raise Exception("catlog init takes exactly one argument")
        box_name = cliArgs[0]
        is_valid_domain = False
        for domain in self._catlog_db.get_domains():
            if box_name.endswith(domain):
                is_valid_domain = True
                break
        if not is_valid_domain:
            raise Exception("Box name " + box_name + " is not under a configured domain.")

        if self._box_db is not None:
            raise Exception("It looks like you're already working under a box!")

        box_root = os.path.join(os.getcwd(), ".catlog")
        if not os.path.isdir(box_root):
            os.mkdir(box_root, 0o700)
        # Instantiate an empty box db
        self._box_root = box_root
        self._box_db = BoxDb(box_root)
        self._box_db.set_config('box_name', cliArgs[0])
        self._box_db.set_config('last_box_index', '0')

    def push(self, cliArgs):
        if len(cliArgs) != 1:
            raise Exception("catlog push expects exactly one argument")
        path = cliArgs[0]
        if not os.path.isfile(path):
            raise Exception("File not found: " + path)

        if self._box_db is None:
            raise Exception("Must be working in a box to push files. Perhaps you need to run `catlog init`?")

        relpath = os.path.relpath(path, os.path.dirname(self._box_root))
        file_status = self._box_db.get_file_status(relpath)
        if file_status is None:
            file_status = FileStatus(filename=relpath)

        with open(path, "rb") as f:
            file_data = f.read()
        _push_data(file_data, False, self._box_db, self._le_client, file_status)

    def commit(self, cliArgs):
        if len(cliArgs) != 0:
            raise Exception("catlog commit doesn't take any arguments")

        if self._box_db is None:
            raise Exception("No box found. `catlog commit` can only be run from within a box!")
        box_index = int(self._box_db.get_config('last_box_index'))
        box_name = self._box_db.get_config('box_name')

        files_to_commit = self._box_db.get_all_files_for_commit()
        if len(files_to_commit) == 0:
            print("Up to date!")
            return
        print("Committing {} new files...".format(len(files_to_commit)))

        file_data = []
        for file_status in files_to_commit:
            log_refs = []
            for log_ref in file_status.log_entries:
                log_refs.append(log_ref)
            file_data.append(catlog_pb2.FileData(
                name=file_status.filename,
                certificate_reference=catlog_pb2.CertificateReference(
                    fingerprint_sha256=file_status.upload_fingerprint_sha256,
                    log_entry=log_refs
                )
            ))

        previous_chunk_ref = None

        fingerprint_sha256 = self._box_db.get_box_fingerprint_sha256()
        leaf_hashes = self._box_db.get_box_refs()
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
            domain = self._catlog_db.pick_domain(False)
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
            print("Minting a certificate that commits {} new files to the box...".format(num_files))
            cert, issuer = self._le_client.mint_cert(domain, "{}.{}".format(box_index + 1, box_name), chunk_data)

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

            # Update the box_db, marking the new box refs and committed files
            self._box_db.mark_files_committed([x.name for x in file_data[:num_files]])
            self._box_db.set_box_refs(fingerprint_sha256, leaf_hashes)
            self._box_db.set_config('last_box_index', str(box_index + 1))
            box_index += 1

            # Finally, reset file_data for next iteration
            file_data = file_data[num_files:]

        return None

    def clone(self, cliArgs):
        if len(cliArgs) != 1:
            raise Exception("Expected exactly only argument to `catlog clone`")
        log_entry = _parse_log_ref(self._ct_log_list, cliArgs[0])
        if log_entry is not None:
            previous_chunk_ref = catlog_pb2.CertificateReference(
                log_entry=[log_entry]
            )
        else:
            last_index = 0
            found_ids = []
            while True:
                index = last_index + 1
                ids = crt_sh.get_cert_ids_by_cn("{}.{}".format(index, cliArgs[0]))
                if len(ids) == 0:
                    break
                last_index = index
                found_ids = ids
            if len(found_ids) == 0:
                raise Exception("Invalid certificate reference: " + cliArgs[0])
            log_entry_refs = []
            for id in ids:
                for leaf_hash in crt_sh.get_leaf_hashes_by_cert_id(id):
                    log_entry_refs.append(catlog_pb2.LogEntryReference(
                        log_id=leaf_hash[0],
                        leaf_hash=leaf_hash[1]
                    ))
            previous_chunk_ref = catlog_pb2.CertificateReference(log_entry=log_entry_refs)

        if self._box_db is not None:
            raise Exception(
                "Already inside a box. `catlog clone` should be issued inside a directory you intend to use as the cloned box")
        box_root = os.path.join(os.getcwd(), ".catlog")
        if not os.path.isdir(box_root):
            os.mkdir(box_root, 0o700)

        self._box_root = box_root
        self._box_db = BoxDb(box_root)
        self._fetch_from(previous_chunk_ref, None)
        # Save the reference we just used to clone this box
        self._box_db.set_box_refs(None, [log_entry])

    def _fetch_from(self, previous_chunk_ref: catlog_pb2.CertificateReference, stop_at_index: Optional[int]):
        box_name = None
        last_box_index = 0

        while previous_chunk_ref is not None and len(previous_chunk_ref.log_entry) > 0:
            ct_log_url = None
            leaf_hash = None
            for ref in previous_chunk_ref.log_entry:
                ct_log_id = ref.log_id
                leaf_hash = ref.leaf_hash
                ct_log_url = self._ct_log_list.lookup_ct_log_by_id(ct_log_id)
                if ct_log_url is not None:
                    break

            if ct_log_url is None:
                raise Exception("Unable to resolve any CT logs from log IDs")

            tbsCert = self._ct_log_list.get_leaf_by_hash(ct_log_url,
                                                         base64.b64encode(leaf_hash).decode('utf-8'))

            # Set last_box_index and box_name from cert's common name
            common_name = cert_encoding.get_subject_cn(tbsCert)
            common_name_match = re.match(r'^([0-9]+)\.(.*)', common_name)
            if common_name_match is not None:
                box_name = common_name_match.group(2)
                cert_index = int(common_name_match.group(1))
                if (stop_at_index is not None) and stop_at_index == cert_index:
                    break
                last_box_index = max(last_box_index, int(common_name_match.group(1)))

            # Pull all the data out of the cert
            encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert), common_name)
            cert_data = catlog_pb2.CertificateData()
            cert_data.ParseFromString(encoded)
            box_chunk = cert_data.box_chunk
            previous_chunk_ref = box_chunk.previous_chunk
            for file_datum in box_chunk.file_data:
                file_status = FileStatus(filename=file_datum.name)
                file_status.upload_complete = True
                file_status.upload_fingerprint_sha256 = file_datum.certificate_reference.fingerprint_sha256
                file_status.committed = True
                for entry in file_datum.certificate_reference.log_entry:
                    file_status.log_entries.append(entry)
                self._box_db.set_file_status(file_status)

        # Save the name and box index
        if box_name is not None:
            self._box_db.set_config('box_name', box_name)
        if last_box_index > 0:
            self._box_db.set_config('last_box_index', str(last_box_index))


    def _format_log_entries(self, log_entries: List[catlog_pb2.LogEntryReference]):
        return " ".join(["{}|{}".format(base64.b64encode(x.log_id).decode('utf-8'),
                                        base64.b64encode(x.leaf_hash).decode('utf-8')) for x in log_entries])

    def status(self, cliArgs):
        if len(cliArgs) != 0:
            raise Exception("No arguments supported for catlog status command.")

        if self._box_db is None:
            raise Exception("Box not found. Perhaps you need to run `catlog init`?")

        refs = self._box_db.get_box_refs()
        if len(refs) > 0:
            print("Box log references")
            print("------------------")
            for ref in refs:
                print("{}|{}".format(
                    base64.b64encode(ref[0]).decode('utf-8'),
                    base64.b64encode(ref[1]).decode('utf-8')
                ))
            print()

        not_fetched = []
        fetched = []
        uncommitted = []
        partially_uploaded = []
        for file in self._box_db.get_all_files():
            full_path = os.path.join(os.path.dirname(self._box_root), file.filename)
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
                print("{}\t{}".format(file.filename, self._format_log_entries(file.log_entries)))
            print()
        if len(uncommitted) > 0:
            print("Uploaded but uncommitted...")
            print("---------------------------")
            for file in uncommitted:
                print("{}\t{}".format(file.filename, self._format_log_entries(file.log_entries)))
            print()
        if len(not_fetched) > 0:
            print("Available but not fetched...")
            print("----------------------------")
            for file in not_fetched:
                print("{}\t{}".format(file.filename, self._format_log_entries(file.log_entries)))

        # FIXME: We should look for and report on files under the box_root that are completely untracked.
        return

    def config(self, cliArgs):
        config_cmd(cliArgs)

    def pull(self, cliArgs):
        if len(cliArgs) != 1:
            raise Exception("catlog pull expects exactly one argument")
        filename_arg = cliArgs[0]
        log_entry_arg = _parse_log_ref(self._ct_log_list, filename_arg)
        if log_entry_arg is not None:
            log_entries = [log_entry_arg]
            output_target = None
        else:
            # Assume this is an actual file path.
            full_path = os.path.abspath(cliArgs[0])
            if os.path.exists(full_path):
                raise Exception("Destination filename already exists: " + full_path)
            if self._box_root is None:
                raise Exception("Not working in a box; cannot pull file by path name.")
            rel_path = os.path.relpath(full_path, os.path.dirname(self._box_root))
            file_status = self._box_db.get_file_status(rel_path)
            if file_status is None:
                raise Exception("File path {} is unknown to box.".format(rel_path))

            log_entries = file_status.log_entries
            output_target = full_path

        data = self._pull_data(log_entries)

        if output_target is None:
            os.write(1, data)  # FIXME: Is there a python constant for stdout?
        else:
            d = os.path.dirname(output_target)
            if not os.path.isdir(d):
                os.mkdir(d)
            with open(output_target, "wb") as f:
                f.write(data)

    def _pull_data(self, log_entries: List[catlog_pb2.LogEntryReference]) -> bytes:
        previous_chunk_ref = catlog_pb2.CertificateReference()
        previous_chunk_ref.log_entry.extend(log_entries)

        data = bytes()
        while previous_chunk_ref is not None and len(previous_chunk_ref.log_entry) > 0:
            resolved = False
            for log_entry in previous_chunk_ref.log_entry:
                ct_log_id = log_entry.log_id
                leaf_hash = log_entry.leaf_hash
                entry_id = log_entry.entry_id

                ct_log_url = self._ct_log_list.lookup_ct_log_by_id(ct_log_id)
                if ct_log_url is None:
                    continue

                try:
                    if entry_id != 0:
                        tbsCert = cert_encoding.get_leaf_by_entry_id(ct_log_url, entry_id,
                                                                     debug_file=sys.stderr)
                    else:
                        tbsCert = self._ct_log_list.get_leaf_by_hash(ct_log_url,
                                                                     base64.b64encode(leaf_hash).decode(
                                                                         'utf-8'), debug_file=sys.stderr)
                except:
                    print("Unable to fetch reference from {}".format(ct_log_url), file=sys.stderr)
                    continue

                encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert),
                                                        cert_encoding.get_subject_cn(tbsCert))
                cert_data = catlog_pb2.CertificateData()
                cert_data.ParseFromString(encoded)
                data_chunk = cert_data.data_chunk
                previous_chunk_ref = data_chunk.previous_chunk
                data = data_chunk.chunk + data

                resolved = True
                break

            if not resolved:
                raise Exception("Unable to resolve any CT logs from log IDs")

        return data

    def add(self, cliArgs):
        if len(cliArgs) != 2:
            raise Exception("catlog add command expects exactly two arguments")
        filename = cliArgs[0]
        log_ref = _parse_log_ref(self._ct_log_list, cliArgs[1])
        if log_ref is None:
            raise Exception("Second argument to `catlog add` must be a log ref: " + cliArgs[1])

        if self._box_db is None:
            raise Exception("`catlog add` can only be run in a box!")
        filename = os.path.relpath(filename, os.path.dirname(self._box_root))

        # Sanity check that the ref is something we can fetch
        ct_log_url = self._ct_log_list.lookup_ct_log_by_id(log_ref.log_id)
        if ct_log_url is None:
            raise Exception("Unable to resolve CT log from log ID")
        tbsCert = self._ct_log_list.get_leaf_by_hash(ct_log_url, base64.b64encode(log_ref.leaf_hash).decode('utf-8'))
        if tbsCert is None:
            raise Exception("Unable to lookup log ref: " + cliArgs[1])

        # Add uploaded but uncommitted status for the filename to the box
        file_status = FileStatus(filename=filename)
        file_status.upload_complete = True
        file_status.committed = False
        file_status.log_entries = [log_ref]

        self._box_db.set_file_status(file_status)

    def fetch(self, cliArgs):
        if len(cliArgs) != 0:
            raise Exception("`catlog fetch` command takes no arguments")
        if self._box_db is None:
            raise Exception("`catlog fetch` can only be run in a box!")

        box_name = self._box_db.get_config('box_name')
        last_box_index = int(self._box_db.get_config('last_box_index'))

        max_found_id = last_box_index
        found_cert_ids = None
        while True:
            next_id = max_found_id + 1
            cert_ids = crt_sh.get_cert_ids_by_cn("{}.{}".format(next_id, box_name))
            if len(cert_ids) == 0:
                break
            max_found_id = next_id
            found_cert_ids = cert_ids

        if max_found_id == last_box_index:
            print("Up to date!")
            return
        print("Updating from {} to {}".format(last_box_index, max_found_id))

        leaf_hashes = []
        for id in found_cert_ids:
            for leaf_hash in crt_sh.get_leaf_hashes_by_cert_id(id):
                leaf_hashes.append(leaf_hash)
        if len(leaf_hashes) == 0:
            raise Exception("Unable to resolve leaf hashes from crt.sh")
        log_entry_refs = []
        for leaf_hash in leaf_hashes:
            log_entry_refs.append(catlog_pb2.LogEntryReference(
                log_id=leaf_hash[0],
                leaf_hash=leaf_hash[1]
            ))
        previous_chunk_ref = catlog_pb2.CertificateReference(log_entry=log_entry_refs)

        self._fetch_from(previous_chunk_ref, last_box_index)
        # Save the reference we just used to update this box
        self._box_db.set_box_refs(None, leaf_hashes)


def _push_data(data: bytes,
               staging: bool,
               box_db: Optional[BoxDb],
               client: le_client.LeClient,
               file_status: Optional[FileStatus]) -> None:
    catlog_db = CatlogDb()
    previous_chunk_ref = None

    if (file_status is not None) and (file_status.upload_offset > 0) and (
            file_status.upload_fingerprint_sha256 is not None) and (len(file_status.log_entries) > 0):
        print("Attempting to push {} bytes of data, starting at previously uploaded offset of {}...".format(len(data),
                                                                                                            file_status.upload_offset))

        data = data[file_status.upload_offset:]
        log_entry_refs = []
        for log_ref in file_status.log_entries:
            log_entry_refs.append(log_ref)
        previous_chunk_ref = catlog_pb2.CertificateReference(
            fingerprint_sha256=file_status.upload_fingerprint_sha256,
            log_entry=log_entry_refs
        )
    else:
        print("Attempting to push {} bytes of data...".format(len(data)))

    while len(data) > 0:
        domain = catlog_db.pick_domain(staging)
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
        cert, issuer = client.mint_cert(domain, domain.domain, chunk_data)

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

        # Update the box_db if working inside a box
        if (box_db is not None) and (file_status is not None):
            new_file_status = FileStatus(id=file_status.id, filename=file_status.filename)
            new_file_status.upload_offset = file_status.upload_offset + chunk_size
            new_file_status.upload_complete = (len(data) <= chunk_size)
            new_file_status.upload_fingerprint_sha256 = fingerprint_sha256
            new_file_status.committed = file_status.committed
            new_file_status.log_entries = log_entry_refs
            box_db.set_file_status(new_file_status)
            file_status = new_file_status

        data = data[chunk_size:]

    return previous_chunk_ref


def _parse_log_ref(ct_log_list: cert_encoding.CtLogList, s: str) -> Optional[catlog_pb2.LogEntryReference]:
    if s.startswith("http") and '|' in s:
        bar_index = s.index('|')
        log_url = s[:bar_index]
        log_id = ct_log_list.lookup_ct_log_id_by_url(log_url)
        if log_id is None:
            raise Exception("Unable to determine log id for {}".format(log_url))
        return catlog_pb2.LogEntryReference(
            log_id=log_id,
            entry_id=int(s[bar_index + 1:])
        )
    elif (len(s) == 89) and s[44] == '|':
        log_ref = catlog_pb2.LogEntryReference()
        log_ref.log_id = base64.b64decode(s[:44])
        log_ref.leaf_hash = base64.b64decode(s[45:])
        return log_ref
    return None


def main(args):
    with CatlogMain() as catlog_main:
        if args[0] == 'push':
            catlog_main.push(args[1:])
        elif args[0] == 'init':
            catlog_main.init(args[1:])
        elif args[0] == 'pull':
            catlog_main.pull(args[1:])
        elif args[0] == 'config':
            catlog_main.config(args[1:])
        elif args[0] == 'status':
            catlog_main.status(args[1:])
        elif args[0] == 'clone':
            catlog_main.clone(args[1:])
        elif args[0] == 'commit':
            catlog_main.commit(args[1:])
        elif args[0] == 'add':
            catlog_main.add(args[1:])
        elif args[0] == 'fetch':
            catlog_main.fetch(args[1:])
        else:
            raise Exception("Unsupported subcommand: " + args[0])

if __name__ == "__main__":
    main(sys.argv[1:])
