import dns.resolver
from FeedGCPWhitelist import Client, GOOGLE_BASE_DNS, fetch_cidr
import json
from collections import namedtuple

mocked_google_dns_address = '_cloud-netblocks1.googleusercontent.com'

RESPONSE_DATA1 = '{"response": { "answer": [["v=spf1 include:_cloud-netblocks1.googleusercontent.com ip4:130.211.64.0/18 ?all"]] } }'
RESPONSE_DATA2 = '{"response": { "answer": [["v=spf1 ip4:208.68.108.0/23 ip6:2600:1900::/35 ?all"]] } }'

def test_fetch_cidr(monkeypatch):
    def mocked_dns_resolver_query(dns_address, _):
        if dns_address == GOOGLE_BASE_DNS:
            data = RESPONSE_DATA1
            x = json.loads(data, object_hook=lambda d: namedtuple('X', d.keys())(*d.values()))
            return x

    monkeypatch.setattr(dns.resolver, "query", mocked_dns_resolver_query)
    cidr_list = fetch_cidr(GOOGLE_BASE_DNS)
    print(cidr_list)


