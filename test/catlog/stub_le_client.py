import base64
import time
from typing import List, Tuple
from unittest import TestCase

import asn1crypto.core
from OpenSSL import crypto

from catlog import cert_encoding
from catlog import ctl_parser_structures
from catlog import le_client
from catlog import stub_crt_sh
from catlog import stub_ct_log
from catlog.catlog_db import CatlogDb


class StubLeClient(le_client.LeClient):
    def __init__(self, ct_log: stub_ct_log.StubCtLog = None):
        catlog_db = CatlogDb(path=":memory:")
        super().__init__(False, catlog_db)

        self.ct_log = ct_log

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = "Fake LE Signing CA"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(-1 * 60 * 60)
        cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        self._issuer = cert
        self._issuer_key = k

    def _mint_cert_with_domains(self, domains: List[str]) -> Tuple[bytes, bytes]:
        sct = ctl_parser_structures.SignedCertificateTimestamp.build(dict(
            sct_version=0,
            id=stub_ct_log.STUB_KEY_ID,
            timestamp=int(time.time_ns() / 1e6),
            extensions=dict(
                Length=0,
                Content=b""
            ),
            signature=dict(
                algorithm=dict(
                    hash="sha256",
                    signature="ecdsa"
                ),
                signatureLength=71,
                signature=b"\x00" * 71
            )
        ))
        serialized_sct = ctl_parser_structures.SerializedSCT.build(dict(
            length=len(sct),
            sct=ctl_parser_structures.SignedCertificateTimestamp.parse(sct)
        ))

        sct_list = ctl_parser_structures.SignedCertificateTimestampList.build(dict(
            list_size=len(serialized_sct),
            sct_list=[ctl_parser_structures.SerializedSCT.parse(serialized_sct)]
        ))
        extn_value = asn1crypto.core.OctetString(sct_list).dump()

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = domains[0]
        cert.add_extensions([
            crypto.X509Extension(
                b"subjectAltName", False, ", ".join([("DNS: " + x) for x in domains]).encode('utf-8')
            ),
            crypto.X509Extension(
                b"1.3.6.1.4.1.11129.2.4.2", False, ("DER:" + extn_value.hex()).encode('utf-8')
            )
        ])
        cert.set_serial_number(int(time.time_ns() / 1.6))
        cert.gmtime_adj_notBefore(-1 * 60 * 60)
        cert.gmtime_adj_notAfter(30 * 24 * 60 * 60)
        cert.set_issuer(self._issuer.get_subject())
        cert.set_pubkey(k)
        cert.sign(self._issuer_key, 'sha256')

        cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        issuer_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, self._issuer)

        self.ct_log.submit(cert_bytes, issuer_bytes)
        return cert_bytes, issuer_bytes


class TestStubLeClient(TestCase):
    def test_mint_cert(self):
        ct_log_list = stub_ct_log.StubCtLogList()
        ct_log = stub_ct_log.StubCtLog(ct_log_list, stub_crt_sh.StubCrtSh())
        try:
            domain = le_client.Domain(
                id=0, domain="foo.bar"
            )
            client = StubLeClient(ct_log=ct_log)
            data = b"Hello, World!" * 100
            (cert, issuer) = client.mint_cert(domain, domain.domain, data)

            leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
            assert (len(leaf_hashes) > 0)
            for leaf_hash in leaf_hashes:
                tbsCert = ct_log_list.get_leaf_by_hash(
                    ct_log_list.lookup_ct_log_by_id(leaf_hash[0]),
                    base64.b64encode(leaf_hash[1]).decode('utf-8'))
                encoded = cert_encoding.domains_to_data(cert_encoding.get_sans(tbsCert),
                                                        cert_encoding.get_subject_cn(tbsCert))
                assert (encoded == data)
        finally:
            ct_log.stop()
