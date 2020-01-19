import pytest
from collections import OrderedDict
from FeedRecordedFuture import get_indicator_type, split_hash_context, get_indicator_context

GET_INDICATOR_TYPE_INPUTS = [
    ('ip', OrderedDict([('Name', '192.168.1.1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IP'),
    ('ip', OrderedDict([('Name', '192.168.1.1/32'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'CIDR'),
    ('ip', OrderedDict([('Name', '2001:db8:a0b:12f0::1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IPv6'),
    ('hash', OrderedDict([('Name', '52483514f07eb14570142f6927b77deb7b4da99f'), ('Algorithm', 'SHA-1'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File SHA-1'),
    ('hash', OrderedDict([('Name', '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59'),
                          ('Algorithm', 'SHA-256'), ('Risk', '89'), ('RiskString', '5/12'),
                          ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File SHA-256'),
    ('hash', OrderedDict([('Name', 'c8092abd8d581750c0530fa1fc8d8318'), ('Algorithm', 'MD5'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File MD5'),
    ('domain', OrderedDict([('Name', 'domaintools.com'), ('Risk', '89'), ('RiskString', '5/12'),
                            ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'Domain'),
    ('url', OrderedDict([('Name', 'www.securityadvisor.io'), ('Risk', '89'), ('RiskString', '5/12'),
                         ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'URL')
]


@pytest.mark.parametrize('indicator_type, csv_item, answer', GET_INDICATOR_TYPE_INPUTS)
def test_get_indicator_type(indicator_type, csv_item, answer):
    returned_indicator_type = get_indicator_type(indicator_type, csv_item)
    assert returned_indicator_type == answer


HASH_CONTEXT = [
    (
        {
            'Value': '52483514f07eb14570142f6927b77deb7b4da99f',
            'Type': 'SHA-1',
            'Rawjson': {'Key': 'Value'}
        },
        {
            'Value': '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59',
            'Type': 'SHA-256',
            'Rawjson': {'Key': 'Value'}
        },
        {
            'Value': 'c8092abd8d581750c0530fa1fc8d8318',
            'Type': 'MD5',
            'Rawjson': {'Key': 'Value'}
        }
    )
]


@pytest.mark.parametrize('hash_entry', HASH_CONTEXT)
def test_split_hash_context(hash_entry):
    sha256_context, md5_context, sha1_context = split_hash_context(hash_entry)
    assert sha256_context == ['42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59']
    assert md5_context == ['c8092abd8d581750c0530fa1fc8d8318']
    assert sha1_context == ['52483514f07eb14570142f6927b77deb7b4da99f']


GET_INDICATOR_CONTEXT_INPUTS = [
    ('IP', '192.168.1.1',
     {'Address': '192.168.1.1'}),
    ('File SHA-1', '52483514f07eb14570142f6927b77deb7b4da99f',
     {'SHA1': '52483514f07eb14570142f6927b77deb7b4da99f'}),
    ('File SHA-256', '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59',
     {'SHA256': '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59'}),
    ('File MD5', 'c8092abd8d581750c0530fa1fc8d8318',
     {'MD5': 'c8092abd8d581750c0530fa1fc8d8318'}),
    ('Domain', 'domaintools.com',
     {'Name': 'domaintools.com'}),
    ('URL', 'www.securityadvisor.io',
     {'Data': 'www.securityadvisor.io'})
]


@pytest.mark.parametrize('indicator_type, indicator_value, expected_context', GET_INDICATOR_CONTEXT_INPUTS)
def test_get_indicators_context(indicator_type, indicator_value, expected_context):
    returned_context = get_indicator_context(indicator_type, indicator_value)
    assert returned_context == expected_context
