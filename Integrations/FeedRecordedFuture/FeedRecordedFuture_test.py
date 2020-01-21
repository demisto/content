import pytest
from collections import OrderedDict
from FeedRecordedFuture import get_indicator_type

GET_INDICATOR_TYPE_INPUTS = [
    ('ip', OrderedDict([('Name', '192.168.1.1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IP'),
    ('ip', OrderedDict([('Name', '192.168.1.1/32'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'CIDR'),
    ('ip', OrderedDict([('Name', '2001:db8:a0b:12f0::1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IPv6'),
    ('hash', OrderedDict([('Name', '52483514f07eb14570142f6927b77deb7b4da99f'), ('Algorithm', 'SHA-1'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('hash', OrderedDict([('Name', '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59'),
                          ('Algorithm', 'SHA-256'), ('Risk', '89'), ('RiskString', '5/12'),
                          ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('hash', OrderedDict([('Name', 'c8092abd8d581750c0530fa1fc8d8318'), ('Algorithm', 'MD5'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('domain', OrderedDict([('Name', 'domaintools.com'), ('Risk', '89'), ('RiskString', '5/12'),
                            ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'Domain'),
    ('url', OrderedDict([('Name', 'www.securityadvisor.io'), ('Risk', '89'), ('RiskString', '5/12'),
                         ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'URL')
]


@pytest.mark.parametrize('indicator_type, csv_item, answer', GET_INDICATOR_TYPE_INPUTS)
def test_get_indicator_type(indicator_type, csv_item, answer):
    returned_indicator_type = get_indicator_type(indicator_type, csv_item)
    assert returned_indicator_type == answer
