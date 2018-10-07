import random
from unittest import TestCase

from . import cert_encoding


class TestCertEncoding(TestCase):
    def test_cert_encoding(self):
        input = b"Hello, World!" * 100
        domains = cert_encoding.data_to_domains(input, "staging.derp.fish")
        random.shuffle(domains)
        data = cert_encoding.domains_to_data(domains, "staging.derp.fish")
        assert (data == input)

    def test_random_data(self):
        dns_suffix = "foo.bar"
        input = bytearray(random.getrandbits(8) for _ in range(cert_encoding.get_bytes_per_cert(dns_suffix)))
        domains = cert_encoding.data_to_domains(input, dns_suffix)
        random.shuffle(domains)
        data = cert_encoding.domains_to_data(domains, dns_suffix)
        assert (data == input)
