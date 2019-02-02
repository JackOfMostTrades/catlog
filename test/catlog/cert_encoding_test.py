import base64
import os.path
import random
import unittest

from catlog import cert_encoding


class TestCertEncoding(unittest.TestCase):
    def test_domains_encode_decode(self):
        input = b"Hello, World!" * 100
        domains = cert_encoding.data_to_domains(input, "x.example.com", "x.example.com")
        random.shuffle(domains)
        data = cert_encoding.domains_to_data(domains, "x.example.com")
        assert (data == input)

    def test_random_domains_encode_decode(self):
        dns_suffix = "foo.bar"
        input = bytearray(random.getrandbits(8) for _ in range(cert_encoding.get_bytes_per_cert(dns_suffix)))
        domains = cert_encoding.data_to_domains(input, "1.prefix." + dns_suffix, dns_suffix)
        random.shuffle(domains)
        data = cert_encoding.domains_to_data(domains, "1.prefix." + dns_suffix)
        assert (data == input)

    def test_find_dns_suffix(self):
        assert cert_encoding.find_dns_suffix(["foo.bar.xyz.baz", "xyz.xyz.baz", "foo.baz"]) == "baz"
        assert cert_encoding.find_dns_suffix(["foo.bar.xyz.baz", "xyz.xyz.baz", "xyz.baz"]) == "xyz.baz"
        assert cert_encoding.find_dns_suffix(["foo.bar.xyz.baz", "xyz.xyz.baz", "foo.xyz.baz"]) == "xyz.baz"
        assert cert_encoding.find_dns_suffix(["foo.xyz.baz", "boo.xyz.baz", "moo.xyz.baz"]) == "xyz.baz"

    def test_domains_encode(self):
        domains = cert_encoding.data_to_domains(b"happy cat", "1.box.cats.foo", "cats.foo")
        assert (len(domains) == 2)
        assert (domains[0] == "1.box.cats.foo")
        assert (domains[1] == "ABUGC4DQPEQGGYLU.cats.foo")

    def test_domains_decode(self):
        data = cert_encoding.domains_to_data(["nodogs.cats", "AB2GCY3PMNQXI.nodogs.cats"], "nodogs.cats")
        assert (data == b"tacocat")

    def test_cert_to_leaf_hashes(self):
        wd = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(wd, "637781105.crt"), "rb") as f:
            cert = cert_encoding.pem_to_der(f.read())
        with open(os.path.join(wd, "8656330.crt"), "rb") as f:
            issuer = cert_encoding.pem_to_der(f.read())
        leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
        assert (len(leaf_hashes) == 2)
        assert (leaf_hashes[0] == (base64.b64decode("u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU="),
                                   base64.b64decode("s6xEbpd/yMb71ZPlk+pQwIOPpL0Vy2Kb1p3A1SXRYmw=")))
        assert (leaf_hashes[1] == (base64.b64decode("VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0="),
                                   base64.b64decode("iJNJZXHlf4Ja1CdO4x6cnKT+alLH442DptAEles1hAI=")))

    @unittest.skipIf("OFFLINE" in os.environ, "Not running online test")
    def test_get_leaf_by_hash(self):
        leaf = cert_encoding.CtLogList().get_leaf_by_hash("https://ct.googleapis.com/skydiver/",
                                              "s6xEbpd/yMb71ZPlk+pQwIOPpL0Vy2Kb1p3A1SXRYmw=")
        sans = cert_encoding.get_sans(leaf)
        assert ("apple.com" in sans)
