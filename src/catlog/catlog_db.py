import base64
import os
import os.path
import sqlite3
import time
from typing import Dict, List, Tuple

home = os.path.expanduser("~")

# The maximum number of Certificates per Registered Domain according to Let's Encrypt rate limits
# https://letsencrypt.org/docs/rate-limits/
DOMAIN_USAGE_LIMIT = 50


class Domain:
    def __init__(self, id=None, domain=None, tld=None):
        if id is None or domain is None:
            raise Exception("id and domain cannot be None")
        if tld is None:
            tld = domain
        self.id = id
        self.domain = domain
        self.tld = tld


class CatlogDb:
    def __init__(self, path=None):
        if path is None:
            home = os.path.expanduser("~")
            catlogDir = os.path.join(home, ".catlog")
            if not os.path.isdir(catlogDir):
                os.mkdir(catlogDir, 0o700)
            path = os.path.join(catlogDir, "catlog.db")
        self._db = sqlite3.connect(path)
        self.initdb()

    def initdb(self):
        seed_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "catlog_db_seed.sql")
        with open(seed_path, "r") as f:
            seed_sql = f.read()
        self._db.executescript(seed_sql)

    def close(self):
        self._db.close()

    def find_all_accounts(self, staging: bool):
        accounts = []
        for row in self._db.execute("SELECT account_id,registration_json,key_json FROM accounts WHERE staging=?",
                                    (1 if staging else 0,)):
            accounts.append(row)
        return accounts

    def load_account(self, staging: bool, account_id: str):
        return self._db.execute(
            "SELECT account_id,registration_json,key_json FROM accounts WHERE staging=? AND account_id=?",
            (1 if staging else 0, account_id,))

    def save_account(self, staging: bool, account_id: str, registration_json: str, key_json: str) -> None:
        self._db.execute("INSERT INTO accounts (staging,account_id,registration_json,key_json) VALUES(?,?,?,?)",
                         (1 if staging else 0, account_id, registration_json, key_json,))
        self._db.commit()

    def add_domain(self, domain: str) -> None:
        row = self._db.execute("SELECT id FROM domains WHERE domain=?", (domain,)).fetchone()
        if row is None:
            self._db.execute("INSERT INTO domains (domain,tld,disabled) VALUES(?,?,0)", (domain, domain,))
        else:
            self._db.execute("UPDATE domain SET disabled=0 WHERE id=?", (row[0],))
        self._db.commit()

    def disable_domain(self, domain: str) -> None:
        self._db.execute("UPDATE domains SET disabled=1 WHERE domain=?", (domain,))
        self._db.commit()

    def get_domains(self) -> Dict[str, Tuple[int, int]]:
        domains = {}
        for row in self._db.execute("SELECT domain FROM domains"):
            domains[row[0]] = (0, 0)

        one_week_ago = int(time.time()) - 7 * 24 * 60 * 60
        for staging in [0, 1]:
            for row in self._db.execute(
                    "SELECT D.domain,COUNT(*) FROM certificate_log L INNER JOIN domains D ON D.id=L.domain_id WHERE L.staging=? AND L.date > ? GROUP BY D.id",
                    (staging, one_week_ago,)):
                name = row[0]
                if name in domains:
                    prior = domains[name]
                else:
                    prior = (0, 0)
                if staging == 0:
                    res = (row[1], prior[1])
                else:
                    res = (prior[0], row[1])
                domains[name] = res
        return domains

    def pick_domain(self, staging: bool) -> Domain:
        one_week_ago = int(time.time()) - 7 * 24 * 60 * 60
        # If there is any domain available where we have not minted any certs, use it
        row = self._db.execute(
            "SELECT id,domain,tld FROM domains WHERE disabled=0 AND id NOT IN (SELECT domain_id FROM certificate_log WHERE staging=? AND date > ?)",
            (1 if staging else 0, one_week_ago,)).fetchone()
        if row is None:
            # Otherwise, look for the least-used domain
            row = self._db.execute(
                "SELECT D.id,COUNT(*) FROM certificate_log L INNER JOIN domains D ON D.id=L.domain_id WHERE D.disabled=0 AND L.staging=? AND L.date > ? GROUP BY D.id ORDER BY COUNT(*) ASC LIMIT 1",
                (1 if staging else 0, one_week_ago,)).fetchone()
            domain_id = row[0]
            domain_usage = row[1]
            if domain_usage >= DOMAIN_USAGE_LIMIT:
                raise Exception("No domains available within domain usage rate limit!")
            row = self._db.execute("SELECT id,domain,tld FROM domains WHERE id=?", (domain_id,)).fetchone()
        return Domain(id=row[0], domain=row[1], tld=row[2])

    def add_certificate_log(self, domain: Domain, fingerprint_sha256: bytes, staging: bool,
                            leaf_hashes: List[Tuple[bytes, bytes]]) -> None:
        cursor = self._db.cursor()
        cursor.execute("INSERT INTO certificate_log (date,domain_id,fingerprint_sha256,staging) VALUES(?,?,?,?)",
                         (str(int(time.time())), domain.id, base64.b64encode(fingerprint_sha256), 1 if staging else 0,))
        certificate_log_id = cursor.lastrowid
        for leaf_hash in leaf_hashes:
            cursor.execute("INSERT INTO certificate_log_ct_entry(certificate_log_id, log_id, leaf_hash) VALUES (?,?,?)",
                           (certificate_log_id,
                            base64.b64encode(leaf_hash[0]).decode('utf-8'),
                            base64.b64encode(leaf_hash[1]).decode('utf-8'),))
        self._db.commit()
