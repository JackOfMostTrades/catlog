from unittest import TestCase

from . import le_client


class TestLeClient(TestCase):
    def test_mint_cert(self):
        self.skipTest("online-test")
        (cert, issuer) = le_client.mint_cert(b"Hello, World!", "staging.derp.fish")
        print(cert.decode('utf-8'))
