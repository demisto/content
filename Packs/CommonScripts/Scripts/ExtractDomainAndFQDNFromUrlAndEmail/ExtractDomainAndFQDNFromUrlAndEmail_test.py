# -*- coding: utf-8 -*-
import demistomock as demisto
from ExtractDomainAndFQDNFromUrlAndEmail import extract_fqdn_or_domain, main
import pytest


@pytest.mark.parametrize('input,fqdn,domain', [  # noqa: E501 disable-secrets-detection
    ('http://this.is.test.com', 'this.is.test.com', 'test.com'),
    ('https://caseapi.phishlabs.com', 'caseapi.phishlabs.com', 'phishlabs.com'),
    ('www.bücher.de', 'www.bücher.de', 'bücher.de'),
    ('https://urldefense.proofpoint.com/v2/url?u=http-3A__go.getpostman.com_y4wULsdG0h0DDMY0Dv00100&d=DwMFaQ&c'
     '=ywDJJevdGcjv4rm9P3FcNg&r=s5kA2oIAQRXsacJiBKmTORIWyRN39ZKhobje2GyRgNs&m'
     '=vN1dVSiZvEoM9oExtQqEptm9Dbvq9tnjACDZzrBLaWI&s=zroN7KQdBCPBOfhOmv5SP1DDzZKZ1y9I3x4STS5PbHA&e=',
     'go.getpostman.com', 'getpostman.com'),  # noqa: E501
    ('hxxps://www[.]demisto[.]com', 'www.demisto.com', 'demisto.com'),
    ('https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftwitter.com%2FPhilipsBeLux&data=02|01'
     '||cb2462dc8640484baf7608d638d2a698|1a407a2d76754d178692b3ac285306e4|0|0|636758874714819880&sdata'
     '=dnJiphWFhnAKsk5Ps0bj0p%2FvXVo8TpidtGZcW6t8lDQ%3D&reserved=0%3E%5bcid:image003.gif@01CF4D7F.1DF62650%5d'
     '%3C',
     '', 'twitter.com'),  # noqa: E501 disable-secrets-detection
    ('dummy@recipient.com', '', 'recipient.com'),
    ('content-test-service-acc@content-test-236508.iam.gserviceaccount.com',
     'content-test-236508.iam.gserviceaccount.com', 'gserviceaccount.com'),  # noqa: E501
    ('CAJaFoefy_acEKaqSMGfojbLzKoUnzfpPcnNemuD6K0oQZ2PikQ@mail.gmail.com', 'mail.gmail.com', 'gmail.com'),
    ('5be9245893ff486d98c3640879bb2657.protect@whoisguard.com', '', 'whoisguard.com'),
    ('test@www.bücher.de', 'www.bücher.de', 'bücher.de'),
    ('test@www[.]demisto[.]com', 'www.demisto.com', 'demisto.com'),
    ('AB@1Ab.Vt', '', ''),
])  # noqa: E124
def test_extract_fqdn_or_domain(input, fqdn, domain):
    extracted_fqdn = extract_fqdn_or_domain(input, is_fqdn=True)
    extracted_domain = extract_fqdn_or_domain(input, is_domain=True)

    assert extracted_fqdn == fqdn
    assert extracted_domain == domain


def test_extract_fqdn_or_domain_empty_indicators(mocker):

    mocker.patch.object(demisto, 'args', return_value={'input': 'AB@1Ab.Vt'})
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0]

    assert results[0] == [{'Contents': [], 'ContentsFormat': 'json', 'Type': 1}]
