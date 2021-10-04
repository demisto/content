import dns.resolver
import json
from FeedGCPWhitelist import fetch_cidr
from collections import namedtuple

mock_root_dns = '_mockDns1.mock.com'
mock_node_dns = '_mockDns2.mock.com'

response_data1 = '{"response": { "answer": [["v=spf1 include:'f"{mock_node_dns}"' ip4:52.15.91.198/18 ?all"]] } }'
response_data2 = '{"response": { "answer": [["v=spf1 ip4:52.86.122.241/23 ip6:e1C::c::/35 ?all"]] } }'

mock_responses_dict = {
    mock_root_dns: response_data1,
    mock_node_dns: response_data2
}


def test_fetch_cidr(monkeypatch):
    def mock_dns_resolver_query(dns_address, _):
        response_json = mock_responses_dict[dns_address]
        return json.loads(response_json, object_hook=lambda d: namedtuple('Answer', d.keys())(*d.values()))

    monkeypatch.setattr(dns.resolver, "query", mock_dns_resolver_query)
    cidr_list = fetch_cidr(mock_root_dns)
    assert len(cidr_list) == 3
    for cidr in cidr_list:
        assert 'type' in cidr
        assert 'ip' in cidr
