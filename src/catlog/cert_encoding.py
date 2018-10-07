import base64
import math

# Each label can be 63 characters long
# The total length (including all dots) can be 253 characters.
# https://stackoverflow.com/questions/32290167/what-is-the-maximum-length-of-a-dns-name
MAX_DNS_NAME_LEN = 253
MAX_DNS_LABEL_LEN = 63
MAX_SANS_PER_CERT = 100


def get_bytes_per_san(dns_suffix):
    num_dots = math.floor(MAX_DNS_NAME_LEN - len(dns_suffix) - 1) / MAX_DNS_LABEL_LEN
    chars_per_san = MAX_DNS_NAME_LEN - len(dns_suffix) - 1 - num_dots
    # base32 encoding has a 5/8 encoding ratio, minus 1 byte reserved as an ordinal
    bytes_per_san = math.floor(chars_per_san * 5 / 8) - 1
    return bytes_per_san


def get_bytes_per_cert(dns_suffix):
    return get_bytes_per_san(dns_suffix) * (MAX_SANS_PER_CERT - 1)


def data_to_domains(raw_data, dns_suffix):
    bytes_per_san = get_bytes_per_san(dns_suffix)
    bytes_per_cert = get_bytes_per_cert(dns_suffix)

    if len(raw_data) > bytes_per_cert:
        raise Exception("Data is too big: {} > {}".format(len(raw_data), bytes_per_cert))

    sans = [dns_suffix]
    data = raw_data
    index = 0
    while len(data) > 0:
        chunk = base64.b32encode(bytes([index]) + data[0:bytes_per_san]).decode('utf-8').rstrip("=")
        index += 1
        san = '.'.join(
            [chunk[i:i + MAX_DNS_LABEL_LEN] for i in range(0, len(chunk), MAX_DNS_LABEL_LEN)]) + '.' + dns_suffix
        sans.append(san)
        data = data[bytes_per_san:]
    return sans


def domains_to_data(domains, dns_suffix):
    datas = []
    for san in domains:
        if san == dns_suffix:
            continue
        encoded = san.rstrip(dns_suffix).replace('.', '')
        encoded += "=" * ((4 - (len(encoded) % 4)) % 4)
        data = base64.b32decode(encoded)
        datas.append({"ordinal": data[0], "data": data[1:]})
    datas.sort(key=lambda x: x["ordinal"])
    result = bytes()
    for data in datas:
        result += data["data"]
    return result
