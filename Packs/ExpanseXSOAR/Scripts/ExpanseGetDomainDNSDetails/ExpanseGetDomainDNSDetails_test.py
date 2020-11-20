from ExpanseGetDomainDNSDetails import make_query, get_domain_dns_details_command

from typing import cast, List, TYPE_CHECKING

import dns.rdatatype
if TYPE_CHECKING:
    import dns.resolver


class MockRData:
    def __init__(self, name, rdtype, rdclass):
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.name = name

    def to_text(self):
        return self.name


class MockAnswer:
    def __init__(self, rrset: List[MockRData]):
        self.rrset = rrset


class MockResolver():
    def __init__(self):
        self.nameservers = []

    def resolve(self, qname, rdtype, rdclass, tcp=None, lifetime=None, raise_on_no_answer=None):
        return MockAnswer(
            [MockRData(f"fake{dns.rdatatype.to_text(rdtype)}", rdtype, rdclass), MockRData("fakename2", "fake", "fake")]
        )


def test_make_query(mocker):
    resolver = cast('dns.resolver.Resolver', MockResolver())
    answer = make_query(resolver, "example.com", "CNAME", False)

    assert len(answer) == 1
    assert 'CNAME' in answer
    assert len(answer['CNAME']) == 1
    assert answer['CNAME'][0] == "fakeCNAME"


def test_get_domain_dns_details_command(mocker):
    mocker.patch('dns.resolver.Resolver', side_effect=MockResolver)
    args = {
        'domain': 'developers.paloaltonetworks.com',
        'server': '1.1.1.1'
    }

    result = get_domain_dns_details_command(args)

    assert result.outputs == {
        'Expanse.DomainDNSDetails': {
            'domain': 'developers.paloaltonetworks.com',
            'server': '1.1.1.1',
            'A': ['fakeA'],
            'AAAA': ['fakeAAAA'],
            'CNAME': ['fakeCNAME'],
            'NS': ['fakeNS']
        }
    }
