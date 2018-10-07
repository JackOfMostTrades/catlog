from unittest import TestCase

from . import catlog_db
from . import le_client


class TestLeClient(TestCase):
    def test_mint_cert(self):
        self.skipTest("online-test")
        catlogDb = catlog_db.CatlogDb()
        client = le_client.LeClient(catlogDb)
        (cert, issuer) = client.mint_cert(b"Hello, World!")
        print(cert.decode('utf-8'))
