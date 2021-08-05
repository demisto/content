# -*- coding: utf-8 -*-
from ExtractDomainFromUrlFormat import extract_domain
from ExtractDomainFromUrlFormat import unescape_url
import pytest


@pytest.mark.parametrize('input,domain', [
    ('http://this.is.test.com', 'test.com'),
    ('http:example.com', 'example.com'),
    ('http:\\\\example.com', 'example.com'),
    ('https://caseapi.phishlabs.com', 'phishlabs.com'),
    (u'www.bücher.de', u'bücher.de'),
    ('https://urldefense.proofpoint.com/v2/url?u=http-3A__go.getpostman.com_y4wULsdG0h0DDMY0Dv00100&d=DwMFaQ&c=ywDJJevdGcjv4rm9P3FcNg&r=s5kA2oIAQRXsacJiBKmTORIWyRN39ZKhobje2GyRgNs&m=vN1dVSiZvEoM9oExtQqEptm9Dbvq9tnjACDZzrBLaWI&s=zroN7KQdBCPBOfhOmv5SP1DDzZKZ1y9I3x4STS5PbHA&e=', 'getpostman.com'),  # noqa: E501
    ('hxxps://www[.]demisto[.]com', 'demisto.com'),
    ('https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftwitter.com%2FPhilipsBeLux&data=02|01||cb2462dc8640484baf7608d638d2a698|1a407a2d76754d178692b3ac285306e4|0|0|636758874714819880&sdata=dnJiphWFhnAKsk5Ps0bj0p%2FvXVo8TpidtGZcW6t8lDQ%3D&reserved=0%3E%5bcid:image003.gif@01CF4D7F.1DF62650%5d%3C', 'twitter.com'),  # noqa: E501 disable-secrets-detection
]
)  # noqa: E124
def test_extract_domain(input, domain):
    res = extract_domain(input)
    assert res == domain


@pytest.mark.parametrize('input,url', [
                        ('http:example.com', 'http://example.com'),
                        ('http:\\\\example.com', 'http://example.com')])  # noqa: E124
def test_unescaped_url(input, url):
    unescaped_urls = unescape_url(input)
    assert unescaped_urls == url
