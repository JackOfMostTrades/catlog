import urllib
import json
import base64
import re

import ctl_parser_structures

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

entry = json.loads(urllib.urlopen('https://ct.googleapis.com/icarus/ct/v1/get-entries?start=235662418&end=235662418').read())['entries'][0]

leaf_cert = ctl_parser_structures.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))

print("Leaf Timestamp: {}".format(leaf_cert.Timestamp))
print("Entry Type: {}".format(leaf_cert.LogEntryType))

if leaf_cert.LogEntryType == "X509LogEntryType":
    # We have a normal x509 entry
    cert_data_string = ctl_parser_structures.Certificate.parse(leaf_cert.Entry).CertData
    chain = [x509.load_der_x509_certificate(cert_data_string, default_backend())]

    # Parse the `extra_data` structure for the rest of the chain
    extra_data = ctl_parser_structures.CertificateChain.parse(base64.b64decode(entry['extra_data']))
    for cert in extra_data.Chain:
        chain.append(x509.load_der_x509_certificate(cert.CertData, default_backend()))
else:
    # We have a precert entry
    extra_data = ctl_parser_structures.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
    chain = [x509.load_der_x509_certificate(extra_data.LeafCert.CertData, default_backend())]

    for cert in extra_data.Chain:
        chain.append(
            x509.load_der_x509_certificate(cert.CertData, default_backend())
        )

# Chain is now an array of X509 objects, leaf certificate first, ready for extraction!
cert = chain[0]
ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
sans = ext.value.get_values_for_type(x509.DNSName)

sanMap = [None for n in range(100)]
for san in sans:
  match = re.match("x([0-9]+)\\.(.*)\\.bbb\\.derp\\.fish", san)
  if match:
    n = int(match.group(1))
    data = match.group(2).replace('.', '')
    sanMap[n] = data

joined = ''
for n in range(len(sanMap)):
  data = sanMap[n]
  if data is not None:
    joined += data

print(joined)
with open('out.jpg', 'wb') as f:
    f.write(base64.b32decode(joined.upper()))
