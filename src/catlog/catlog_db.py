import base64
import os
import os.path
import sqlite3
import time

home = os.path.expanduser("~")


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
    def __init__(self):
        home = os.path.expanduser("~")
        catlogDir = os.path.join(home, ".catlog")
        if not os.path.isdir(catlogDir):
            os.mkdir(catlogDir, 0o700)
        self._db = sqlite3.connect(os.path.join(catlogDir, "catlog.db"))
        self.initdb()

    def initdb(self):
        seed_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "catlog_db_seed.sql")
        with open(seed_path, "r") as f:
            seed_sql = f.read()
        self._db.executescript(seed_sql)

    def close(self):
        self._db.close()

    def find_all_accounts(self):
        accounts = []
        for row in self._db.execute("SELECT account_id,registration_json,key_json FROM accounts"):
            accounts.append(row)
        return accounts

    def load_account(self, account_id: str):
        return self._db.execute("SELECT account_id,registration_json,key_json FROM accounts WHERE account_id=?",
                                (account_id,))

    def save_account(self, account_id: str, registration_json: str, key_json: str) -> None:
        self._db.execute("INSERT INTO accounts (account_id,registration_json,key_json) VALUES(?,?,?)",
                         (account_id, registration_json, key_json,))
        self._db.commit()

    def pick_domain(self, staging: bool) -> Domain:
        one_week_ago = int(time.time()) - 7 * 24 * 60 * 60
        # If there is any domain available where we have not minted any certs, use it
        row = self._db.execute(
            "SELECT id,domain,tld FROM domains WHERE id NOT IN (SELECT domain_id FROM certificate_log WHERE staging=? AND date > ?)",
            (1 if staging else 0, one_week_ago,)).fetchone()
        if row is None:
            # Otherwise, look for the least-used domain
            row = self._db.execute(
                "SELECT domain_id FROM certificate_log WHERE staging=? AND date > ? GROUP BY domain_id ORDER BY COUNT(*) DESC LIMIT 1",
                (1 if staging else 0, one_week_ago,)).fetchone()
            row = self._db.execute("SELECT id,domain,tld FROM domains WHERE id=?", (row[0],)).fetchone()
        return Domain(id=row[0], domain=row[1], tld=row[2])

    def add_certificate_log(self, domain: Domain, fingerprint_sha256: bytes, staging: bool) -> None:
        self._db.execute("INSERT INTO certificate_log (date,domain_id,fingerprint_sha256,staging) VALUES(?,?,?,?)",
                         (str(int(time.time())), domain.id, base64.b64encode(fingerprint_sha256), 1 if staging else 0,))
        self._db.commit()
