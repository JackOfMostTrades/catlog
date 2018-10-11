# https://tools.ietf.org/html/rfc6962
from construct import Struct, Switch, Byte, Int16ub, Int64ub, Enum, Bytes, Int24ub, this, GreedyRange

CtExtensions = Struct(
    "Length" / Int16ub,
    "Content" / Bytes(this.Length)
)

Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

PreCert = Struct(
    "IssuerKeyHash" / Bytes(32),
    "TBSCertificateLength" / Int24ub,
    "TBSCertificate" / Bytes(this.TBSCertificateLength)
)

TimestampedEntry = Struct(
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / Switch(this.LogEntryType,
                               {
                                   "X509LogEntryType": Certificate,
                                   "PrecertLogEntryType": PreCert
                               }),
    "Extensions"      / CtExtensions
)

MerkleTreeLeaf = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "TimestampedEntry" / TimestampedEntry
)

HashAlgorithm = Enum(Byte, none=0, md5=1, sha1=2, sha224=3, sha256=4, sha384=5, sha512=6)
SignatureAlgorithm = Enum(Byte, anonymous=0, rsa=1, dsa=2, ecdsa=3)

SignatureAndHashAlgorithm = Struct(
    "hash" / HashAlgorithm,
    "signature" / SignatureAlgorithm
)

DigitallySigned = Struct(
    "algorithm" / SignatureAndHashAlgorithm,
    "signatureLength" / Int16ub,
    "signature" / Bytes(this.signatureLength)
)

SignedCertificateTimestamp = Struct(
    "sct_version" / Byte,
    "id" / Bytes(32),
    "timestamp" / Int64ub,
    "extensions" / CtExtensions,
    "signature" / DigitallySigned
)

SerializedSCT = Struct(
    "length" / Int16ub,
    "sct" / SignedCertificateTimestamp
)

SignedCertificateTimestampList = Struct(
    "list_size" / Int16ub,
    "sct_list" / GreedyRange(SerializedSCT)
)