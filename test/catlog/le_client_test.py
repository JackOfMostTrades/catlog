import base64
from unittest import TestCase

from . import catlog_db
from . import le_client


class TestLeClient(TestCase):
    def test_mint_cert(self):
        self.skipTest("online-test")
        catlogDb = catlog_db.CatlogDb()
        domain = catlogDb.pick_domain(True)
        client = le_client.LeClient(catlogDb)
        (cert, issuer) = client.mint_cert(domain, b"Hello, World!" * 100)
        print(base64.b64encode(cert).decode('utf-8'))
