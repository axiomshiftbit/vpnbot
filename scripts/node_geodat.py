"""Xray geodata files for the node's own lists (GeoIPList / GeoSiteList protobuf).

Rules reference a list as ext:<file>:<code>. Xray builds one matcher per file and
code, so the core config stays small however many rules use a large list.
"""
import ipaddress

IP_FILE = 'vpnbot-ip.dat'
SITE_FILE = 'vpnbot-site.dat'
# geodat.proto Domain.Type: Substr, Regex, Domain (with subdomains), Full.
DOMAIN_TYPES = {'keyword': 0, 'regexp': 1, 'domain': 2, 'full': 3}


def varint(value):
    out = bytearray()
    while value > 0x7f:
        out.append(value & 0x7f | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, payload):
    """Length-delimited field."""
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def entry(code, items):
    # Xray upper-cases the code of a rule and matches it as the entry's first field.
    code = code.upper().encode('ascii')
    if not 1 <= len(code) <= 127:
        raise ValueError('invalid geodata code')
    return field(1, field(1, code) + b''.join(items))


def geoip(lists):
    """{code: [CIDR, ...]} -> GeoIPList."""
    result = []
    for code, cidrs in lists.items():
        items = []
        for cidr in cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            items.append(field(2, field(1, network.network_address.packed) + varint(2 << 3) + varint(network.prefixlen)))
        result.append(entry(code, items))
    return b''.join(result)


def geosite(lists):
    """{code: ['full:a.test', 'keyword:video', ...]} -> GeoSiteList."""
    result = []
    for code, domains in lists.items():
        items = []
        for token in domains:
            kind, _, value = token.partition(':')
            if kind not in DOMAIN_TYPES or not value:
                raise ValueError('invalid domain matcher')
            items.append(field(2, varint(1 << 3) + varint(DOMAIN_TYPES[kind]) + field(2, value.encode())))
        result.append(entry(code, items))
    return b''.join(result)


def reference(kind, code):
    return 'ext:' + (IP_FILE if kind == 'ip' else SITE_FILE) + ':' + code.upper()
