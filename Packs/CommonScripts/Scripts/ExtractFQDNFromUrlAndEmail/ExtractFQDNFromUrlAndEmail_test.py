# -*- coding: utf-8 -*-
from ExtractFQDNFromUrlAndEmail import extract_fqdn
import pytest


@pytest.mark.parametrize(
    "input,fqdn",
    [  # noqa: E501 disable-secrets-detection
        ("http://this.is.test.com", "this.is.test.com"),
        ("https://caseapi.phishlabs.com", "caseapi.phishlabs.com"),
        # output needs to be bytes string utf-8 encoded (otherwise python loop demisto.results fails)
        (u"www.bücher.de", u"www.bücher.de".encode("utf-8")),
        (
            "https://urldefense.proofpoint.com/v2/url?u=http-3A__go.getpostman.com_y4wULsdG0h0DDMY0Dv00100&d=DwMFaQ&c=yw"
            "DJJevdGcjv4rm9P3FcNg&r=s5kA2oIAQRXsacJiBKmTORIWyRN39ZKhobje2GyRgNs&m=vN1dVSiZvEoM9oExtQqEptm9Dbvq9tnjACDZzr"
            "BLaWI&s=zroN7KQdBCPBOfhOmv5SP1DDzZKZ1y9I3x4STS5PbHA&e=",
            "go.getpostman.com",
        ),  # noqa: E501
        ("hxxps://www[.]demisto[.]com", "www.demisto.com"),
        (
            "https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Ftwitter.com%2FPhilipsBeLux&data=02|01||c"
            "b2462dc8640484baf7608d638d2a698|1a407a2d76754d178692b3ac285306e4|0|0|636758874714819880&sdata=dnJiphWFhnAKs"
            "k5Ps0bj0p%2FvXVo8TpidtGZcW6t8lDQ%3D&reserved=0%3E%5bcid:image003.gif@01CF4D7F.1DF62650%5d%3C",
            "",
        ),  # noqa: E501 disable-secrets-detection
    ],
)  # noqa: E124
def test_extract_domain(input, fqdn):
    extracted_fqdn = extract_fqdn(input)
    assert extracted_fqdn == fqdn
