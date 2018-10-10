import base64
import os
import os.path
import sqlite3
from typing import List, Optional, Tuple


def discover_box_root() -> Optional[str]:
    dir = os.getcwd()
    while dir != "/":
        box_root = os.path.join(dir, ".catlog")
        box_db = os.path.join(box_root, "box.db")
        if os.path.isfile(box_db):
            return box_root
        dir = os.path.dirname(dir)
    return None


class FileStatus:
    def __init__(self, id=0, filename=None):
        if filename is None:
            raise Exception("Filename parameter is required")
        self.id = id
        self.filename = filename
        self.upload_offset = 0
        self.upload_complete = False
        self.upload_fingerprint_sha256 = None
        self.committed = False
        self.log_entries = []


class BoxDb:
    def __init__(self, box_root):
        box_db = os.path.join(box_root, "box.db")
        self._db = sqlite3.connect(box_db)
        self.initdb()

    def initdb(self):
        seed_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "box_db_seed.sql")
        with open(seed_path, "r") as f:
            seed_sql = f.read()
        self._db.executescript(seed_sql)

    def close(self):
        self._db.close()

    def get_config(self, key: str) -> Optional[str]:
        row = self._db.execute("SELECT value FROM box_config WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        return row[0]

    def set_config(self, key: str, value: str) -> None:
        self._db.execute("UPDATE box_config SET value=? WHERE key=?", (value, key,))
        self._db.commit()

    def get_box_fingerprint_sha256(self) -> Optional[bytes]:
        val = self.get_config('fingerprint_sha256')
        if val is None:
            return None
        return base64.b64decode(val)

    def get_box_refs(self) -> List[Tuple[bytes, bytes]]:
        refs = []
        for row in self._db.execute("SELECT log_id,leaf_hash FROM box_ct_entry"):
            refs.append((
                base64.b64decode(row[0]),
                base64.b64decode(row[1])
            ))
        return refs

    def set_box_refs(self, fingerprint_sha256: Optional[bytes], log_refs: List[Tuple[bytes, bytes]]) -> None:
        self._db.execute("DELETE FROM box_config WHERE key='fingerprint_sha256'")
        if fingerprint_sha256 is not None:
            self._db.execute("INSERT INTO box_config (key,value) VALUES('fingerprint_sha256',?)",
                             (base64.b64encode(fingerprint_sha256).decode('utf-8'),))
        self._db.execute("DELETE FROM box_ct_entry")
        for log_ref in log_refs:
            self._db.execute("INSERT INTO box_ct_entry (log_id,leaf_hash) VALUES(?,?)", (
                base64.b64encode(log_ref[0]).decode('utf-8'),
                base64.b64encode(log_ref[1]).decode('utf-8'),
            ))
        self._db.commit()

    def get_all_files(self) -> List[FileStatus]:
        files = []
        for row in self._db.execute(
                "SELECT id,filename,upload_offset,upload_complete,upload_fingerprint_sha256,committed FROM file_status"):
            file = FileStatus(id=row[0], filename=row[1])
            file.upload_offset = row[2]
            file.upload_complete = (row[3] != 0)
            file.upload_fingerprint_sha256 = None if row[4] is None else base64.b64decode(row[4])
            file.committed = (row[5] != 0)
            files.append(file)
        return files

    def get_all_files_for_commit(self) -> List[FileStatus]:
        files = {}
        for row in self._db.execute(
                "SELECT id,filename,upload_offset,upload_complete,upload_fingerprint_sha256,committed FROM file_status WHERE upload_complete<>0 AND committed=0"):
            file = FileStatus(id=row[0], filename=row[1])
            file.upload_offset = row[2]
            file.upload_complete = (row[3] != 0)
            file.upload_fingerprint_sha256 = None if row[4] is None else base64.b64decode(row[4])
            file.committed = (row[5] != 0)
            files[file.id] = file
        for row in self._db.execute(
                "SELECT file_status_id,log_id,leaf_hash FROM file_status_ct_entry E INNER JOIN file_status S ON S.id=E.file_status_id WHERE upload_complete<>0 AND committed=0"):
            id = row[0]
            files[row[0]].log_entries.append((
                base64.b64decode(row[1]),
                base64.b64decode(row[2])))
        return list(files.values())

    def get_file_status(self, filename: str) -> Optional[FileStatus]:
        row = self._db.execute(
            "SELECT id,filename,upload_offset,upload_complete,upload_fingerprint_sha256,committed FROM file_status WHERE filename=?",
            (filename,)).fetchone()
        if row is None:
            return None
        file = FileStatus(id=row[0], filename=row[1])
        file.upload_offset = row[2]
        file.upload_complete = (row[3] != 0)
        file.upload_fingerprint_sha256 = None if row[4] is None else base64.b64decode(row[4])
        file.committed = (row[5] != 0)

        for row in self._db.execute("SELECT log_id,leaf_hash FROM file_status_ct_entry WHERE file_status_id=?",
                                    (file.id,)):
            file.log_entries.append((base64.b64decode(row[0]),
                                     base64.b64decode(row[1])))
        return file

    def set_file_status(self, file: FileStatus) -> None:
        cursor = self._db.cursor()
        id_row = cursor.execute("SELECT id FROM file_status WHERE filename=?", (file.filename,)).fetchone()
        if id_row is None:
            cursor.execute(
                "INSERT INTO file_status (filename, upload_offset, upload_complete, upload_fingerprint_sha256, committed) VALUES (?,?,?,?,?)",
                (file.filename,
                 file.upload_offset,
                 1 if file.upload_complete else 0,
                 base64.b64encode(file.upload_fingerprint_sha256).decode('utf-8'),
                 1 if file.committed else 0,))
            id = cursor.lastrowid
        else:
            id = id_row[0]
            cursor.execute(
                "UPDATE file_status SET upload_offset=?, upload_complete=?, upload_fingerprint_sha256=?, committed=? WHERE id=?",
                (file.upload_offset,
                 1 if file.upload_complete else 0,
                 base64.b64encode(file.upload_fingerprint_sha256).decode('utf-8'),
                 1 if file.committed else 0,
                 id,))
        cursor.execute("DELETE FROM file_status_ct_entry WHERE file_status_id=?", (id,))
        for log_entry in file.log_entries:
            cursor.execute("INSERT INTO file_status_ct_entry (file_status_id, log_id, leaf_hash) VALUES (?,?,?)",
                           (id,
                            base64.b64encode(log_entry[0]).decode('utf-8'),
                            base64.b64encode(log_entry[1]).decode('utf-8'),))
        self._db.commit()

    def mark_files_committed(self, names: List[str]) -> None:
        cursor = self._db.cursor()
        for name in names:
            cursor.execute("UPDATE file_status SET committed=1 WHERE filename=?", (name,))
        self._db.commit()
