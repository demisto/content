# -*- coding: utf-8 -*-
import demistomock as demisto
from ExtractDomainAndFQDNFromUrlAndEmail import extract_fqdn, main
import pytest


@pytest.mark.parametrize('input,fqdn', [  # noqa: E501 disable-secrets-detection
    ('www.static.attackiqtes.com', 'www.static.attackiqtes.com'),
    ('http:www.static.attackiqtes.com', 'www.static.attackiqtes.com'),
    ('attackiqtes.co.il', 'attackiqtes.co.il'),
    ('ftp://www.test.com/test2/dev', 'www.test.com'),
    ('http://www.test.com/test2/dev', 'www.test.com'),
    ('www.test.fake', ''),
    ('www[.]demisto[.]com', 'www.demisto.com'),
    ('www[.]demisto[.]test2.com', 'www.demisto.test2.com'),
    ('test.zip', ''),
    ('https%3A%2F%2Fdulunggakada40[.]com', 'dulunggakada40.com'),
    ('https%3A%2F%2Fpath.test.com', 'path.test.com'),
    ('https://urldefense.com/v3/__http://survey.lavulcamktg.cl/index.php/783758', 'survey.lavulcamktg.cl'),
    ('this.is.test.com', 'this.is.test.com'),
    ('caseapi.phishlabs.com', 'caseapi.phishlabs.com'),
    ('www.bücher.de', 'www.bücher.de'),
    ('https://urldefense.proofpoint.com/v2/url?u=http-3A__go.getpostman.com_y4wULsdG0h0DDMY0Dv00100&d=DwMFaQ&c'
     '=ywDJJevdGcjv4rm9P3FcNg&r=s5kA2oIAQRXsacJiBKmTORIWyRN39ZKhobje2GyRgNs&m'
     '=vN1dVSiZvEoM9oExtQqEptm9Dbvq9tnjACDZzrBLaWI&s=zroN7KQdBCPBOfhOmv5SP1DDzZKZ1y9I3x4STS5PbHA&e=',
     'go.getpostman.com'),  # noqa: E501
    ('www[.]demisto[.]com', 'www.demisto.com'),
    ('hxxp://www[.]demisto[.]com', 'www.demisto.com'),
    ('www[.]demisto.test[.]com', 'www.demisto.test.com'),
    ('https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftwitter.com%2FPhilipsBeLux&data=02|01'
     '||cb2462dc8640484baf7608d638d2a698|1a407a2d76754d178692b3ac285306e4|0|0|636758874714819880&sdata'
     '=dnJiphWFhnAKsk5Ps0bj0p%2FvXVo8TpidtGZcW6t8lDQ%3D&reserved=0%3E%5bcid:image003.gif@01CF4D7F.1DF62650%5d'
     '%3C', 'twitter.com'),  # noqa: E501 disable-secrets-detection
])  # noqa: E124
def test_extract_fqdn_or_domain(input, fqdn):
    extracted_fqdn = extract_fqdn(input)
    # extracted_domain = extract_fqdn_or_domain(input, is_domain=True)

    assert extracted_fqdn == fqdn
    # assert extracted_domain == domain


def test_extract_fqdn_or_domain_empty_indicators(mocker):
    mocker.patch.object(demisto, 'args', return_value={'input': '1Ab.Vt'})
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0]

    assert results[0] == [{'Contents': [], 'ContentsFormat': 'json', 'Type': 1}]
