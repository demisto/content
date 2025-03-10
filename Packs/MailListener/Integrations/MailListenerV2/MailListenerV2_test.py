from datetime import datetime
from freezegun import freeze_time
import pytest

MAIL_STRING = rb"""Delivered-To: to@test1.com
MIME-Version: 1.0
From: John Smith <from@test1.com>
Date: Mon, 10 Aug 2020 10:17:16 +0300
Subject: Testing email for mail listener
To: to@test1.com
Content-Type: multipart/alternative; boundary="0000000000002b271405ac80bf8b"


--0000000000002b271405ac80bf8b
Content-Type: text/plain; charset="UTF-8"



--0000000000002b271405ac80bf8b
Content-Type: text/html; charset="UTF-8"

<div dir="ltr"><br></div>
<p>C:\Users</p>
<p>C:\\Users</p>

--0000000000002b271405ac80bf8b--
"""

MAIL_STRING_NO_DATE = rb"""Delivered-To: to@test1.com
MIME-Version: 1.0
From: John Smith <from@test1.com>
Date:
Subject: Testing email for mail listener
To: to@test1.com
Content-Type: multipart/alternative; boundary="0000000000002b271405ac80bf8b"


--0000000000002b271405ac80bf8b
Content-Type: text/plain; charset="UTF-8"



--0000000000002b271405ac80bf8b
Content-Type: text/html; charset="UTF-8"

<div dir="ltr"><br></div>
<p>C:\Users</p>
<p>C:\\Users</p>

--0000000000002b271405ac80bf8b--
"""

MAIL_STRING_NOT_BYTES = r"""Delivered-To: to@test1.com
MIME-Version: 1.0
From: John Smith <from@test1.com>
Date: Mon, 10 Aug 2020 10:17:16 +0300
Subject: Testing email for mail listener
To: to@test1.com
Content-Type: multipart/alternative; boundary="0000000000002b271405ac80bf8b"


--0000000000002b271405ac80bf8b
Content-Type: text/plain; charset="UTF-8"



--0000000000002b271405ac80bf8b
Content-Type: text/html; charset="UTF-8"

<div dir="ltr"><br></div>
<p>C:\Users</p>

--0000000000002b271405ac80bf8b--
"""
EXPECTED_LABELS = [
    {"type": "Email/from", "value": "from@test1.com"},
    {"type": "Email/format", "value": "multipart/alternative"},
    {"type": "Email/text", "value": ""},
    {"type": "Email/subject", "value": "Testing email for mail listener"},
    {"type": "Email/headers/Delivered-To", "value": "to@test1.com"},
    {"type": "Email/headers/MIME-Version", "value": "1.0"},
    {"type": "Email/headers/From", "value": "John Smith <from@test1.com>"},
    {"type": "Email/headers/Date", "value": "Mon, 10 Aug 2020 10:17:16 +0300"},
    {"type": "Email/headers/Subject", "value": "Testing email for mail listener"},
    {"type": "Email/headers/To", "value": "to@test1.com"},
    {"type": "Email/headers/Content-Type", "value": 'multipart/alternative; boundary="0000000000002b271405ac80bf8b"'},
    {"type": "Email", "value": "to@test1.com"},
    {"type": "Email/html", "value": '<div dir="ltr"><br></div>\n<p>C:\\\\Users</p>\n<p>C:\\\\Users</p>'},
]


@freeze_time("2022-12-11 13:40:00 UTC")
@pytest.mark.parametrize(
    "mail_string, mail_date", [(MAIL_STRING, "2020-08-10T07:17:16+00:00"), (MAIL_STRING_NO_DATE, "2022-12-11T13:40:00+00:00")]
)
def test_convert_to_incident(mail_string, mail_date):
    """
    Given:
        - Bytes representation of a mail

        When:
        - Parsing it to incidents

        Then:
        - Validate the 'attachments', 'occurred', 'details' and 'name' fields are parsed as expected
    """
    from MailListenerV2 import Email

    email = Email(mail_string, False, False, 0)
    incident = email.convert_to_incident()
    assert incident["occurred"] == mail_date
    assert incident["details"] == email.text or email.html
    assert incident["name"] == email.subject


@pytest.mark.parametrize(
    "time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from, expected_query",
    # noqa: E501
    [
        (
            datetime(year=2020, month=10, day=1),  # noqa: E126
            False,  # noqa: E126
            ["test1@mail.com", "test2@mail.com"],
            ["test1.com", "domain2.com"],
            4,
            [
                "OR",
                "OR",
                "OR",
                "FROM",
                "domain2.com",
                "FROM",
                "test1.com",
                "FROM",
                "test1@mail.com",
                "FROM",
                "test2@mail.com",
                "SINCE",
                datetime(year=2020, month=10, day=1),
                "UID",
                "4:*",
            ],
        ),
        (
            datetime(year=2020, month=10, day=1),  # noqa: E126
            True,  # noqa: E126
            ["test1@mail.com", "test2@mail.com"],
            ["test1.com", "domain2.com"],
            4,
            [
                "OR",
                "OR",
                "OR",
                "HEADER",
                "FROM",
                "domain2.com",
                "HEADER",
                "FROM",
                "test1.com",
                "HEADER",
                "FROM",
                "test1@mail.com",
                "HEADER",
                "FROM",
                "test2@mail.com",
                "SINCE",
                datetime(year=2020, month=10, day=1),
                "UID",
                "4:*",
            ],
        ),
        (
            None,  # noqa: E126
            "",  # noqa: E126
            [],
            [],
            1,
            ["UID", "1:*"],
        ),
    ],
)
def test_generate_search_query(
    time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from, expected_query
):
    """
    Given:
        - The date from which mails should be queried
        - A list of email addresses from which mails should be queried
        - A list of domains from which mails should be queried

        When:
        - Generating search query from these arguments

        Then:
        - Validate the search query as enough 'OR's in the beginning (Σ(from n=0to(len(addresses)+len(domains)))s^(n-1))
        - Validate the search query has FROM before each address or domain
        - Validate query has SINCE before the datetime object
    """
    from MailListenerV2 import generate_search_query

    assert (
        generate_search_query(
            time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from
        )
        == expected_query
    )


def test_generate_labels():
    """
    Given:
    - Bytes representation of a mail

    When:
    - Generating mail labels

    Then:
    - Validate all expected labels are in the generated labels
    """
    from MailListenerV2 import Email

    email = Email(MAIL_STRING, False, False, 0)
    labels = email._generate_labels()
    for label in EXPECTED_LABELS:
        assert label in labels, f"Label {label} was not found in the generated labels, {labels}"


def mock_email():
    from unittest.mock import patch
    from MailListenerV2 import Email

    with patch.object(Email, "__init__", lambda a, b, c, d, e: None):
        email = Email("data", False, False, 0)
        email.id = 0
        email.date = 0
        return email


@pytest.mark.parametrize(
    "src_data, expected", [({1: {b"RFC822": rb"C:\User\u"}}, rb"C:\User\u"), ({2: {b"RFC822": rb"C:\User\u"}}, rb"C:\User\u")]
)
def test_fetch_mail_gets_bytes(mocker, src_data, expected):
    """
    Given:
        A byte string representing response from API
    When:
        1. The string returns as string
        2. The string returns as bytes
    Then:
        validates Email is called with a bytes string.
    """
    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mail_mocker = mocker.patch("MailListenerV2.Email", return_value=mock_email())
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(IMAPClient, "search", return_value=[1])
    mocker.patch.object(IMAPClient, "fetch", return_value=src_data)
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    fetch_mails(IMAPClient("http://example_url.com"))
    assert mail_mocker.call_args[0][0] == expected


def test_fetch_mail__default_uid(
    mocker,
):
    """
    Given:
        - No uid is passed to fetch_mails function
    When:
        - Fetching mails
    Then:
        - Validate search query is empty
    """
    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mocker.patch("MailListenerV2.Email")
    mocker.patch.object(demisto, "debug")
    search_mocker = mocker.patch.object(IMAPClient, "search", return_value=[1])
    mocker.patch.object(IMAPClient, "fetch")
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    fetch_mails(IMAPClient("http://example_url.com"))
    assert search_mocker.call_args[0][0] == []  # default uid is 0 so no search query is passed


def test_invalid_mail_object_handling(mocker):
    """
    Given:
        - Fetch response with 3 mails, the 2nd being invalid mail
    When:
        - Fetching mails
    Then:
        - Validate only 2 valid mails are returned
        - Validate skipping invalid mail and printing relevant debug message
    """
    src_data = {1: {b"RFC822": rb"C:\User1\u"}, 2: {b"RFC822": rb"C:\User2\u"}, 3: {b"RFC822": rb"C:\User3\u"}}

    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mock_email_1 = mock_email()
    mock_email_3 = mock_email()
    mock_email_1.id, mock_email_3.id = 10, 11

    mocker.patch("MailListenerV2.Email", side_effect=[mock_email_1, Exception("Invalid Mail"), mock_email_3])
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(IMAPClient, "search", return_value=[1])
    mocker.patch.object(IMAPClient, "fetch", return_value=src_data)
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    mails_fetched, messages_fetched, _ = fetch_mails(IMAPClient("http://example_url.com"))
    assert len(mails_fetched) == 2
    assert messages_fetched == [10, 11]


def test_get_eml_attachments():
    from MailListenerV2 import Email
    import email

    # Test an email with a PNG attachment
    with open("test_data/eml-with-jpeg.eml", "rb") as f:
        msg = email.message_from_bytes(f.read())
    res = Email.get_eml_attachments(msg.as_bytes())
    assert res == []
    # Test an email with EML attachment
    with open("test_data/eml-with-eml-with-attachment.eml", "rb") as f:
        msg = email.message_from_bytes(f.read())
    res = Email.get_eml_attachments(msg.as_bytes())
    assert res[0]["filename"] == "Test with an image.eml"

    # Test an email with EML attachment with an EML attachment
    with open("test_data/eml_test_with_attachment_with_eml_attachment.eml", "rb") as f:
        msg = email.message_from_bytes(f.read())
    res = Email.get_eml_attachments(msg.as_bytes())

    assert res[0]["filename"] == "Fwd: MOIS DE MARSè.eml"
    assert isinstance(res[0]["payload"], bytes)


@pytest.mark.parametrize(
    "cert_and_key",
    [
        # - cert and key are in the integration instance parameters
        # - private key is OpenSSL format
        # *** The cert and key below are not used in the real services, and only used for testing.
        (
            {
                "password": "-----BEGIN CERTIFICATE----- "
                "MIIDlzCCAX+gAwIBAgIUbN3atZY05K7SilRtY78y2ZON28QwDQYJKoZIhvcNAQEN "
                "BQAwJTEjMCEGA1UEAwwaTWFpbCBMaXN0ZW5lciBUZXN0IFJvb3QgQ0EwHhcNMjMw "
                "NzExMDA1NzI4WhcNMzMwNzExMDA1NzI4WjAaMRgwFgYDVQQDDA90ZXN0IGNsaWVu "
                "dCBlY2MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARFTRK4qjfOkK25NAssTni1/bKD "
                "TvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzERE "
                "gtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGujeDB2MB8GA1UdIwQYMBaAFDh6 "
                "N1cbIXsS4uo15Ha9fKZrEbcHMB0GA1UdDgQWBBRFSQMsVOPCmzMbvjnrYMGF1ZNs "
                "8DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggr "
                "BgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAJKmlIV9Du9pnA98vw4GsurAeXU3Y "
                "KlzMyffzIVF+CGTpUFmXIGu1KccZREGQEZpxotYF71HCCqPBUcQD8rRoetxX3wa6 "
                "iqk6Q3Pm9Jt8/P365vydvcsKvTEeP8NTWKVip7U8xgAIjykBdnEPu9Uq7x+bePiG "
                "Pqd2Mpzr+mydbU/3mzrZXm/3B0aNiYZdXSpkF4qwZ7lakFvn0MI1M9+B2Am+rNdJ "
                "AoBBQTwS+1pUZoKV3gXMRWKCHj5cbltf1+Lzhh64A8s8k0o1cFyXfSFZ/PJI2rve "
                "ZOKGQ8qIeF3FPCaX5TVvla9J5Mxz5ETXv5zWpK/H4VgPbLf1cZPGFHnYatKkXMvM "
                "05UZ1FmdmJSS8CQQ7AwRsAyWOrbnfUf3Xv5UVFlgGYbsM1+ENbs9Mpn9mq0zq7+J "
                "ONxkmyrkP3Gi/ZK1k9fZuE+WGrnzkP6zUMA76Zr2uH8Gq5Bt89jTl9gAAYuaIDSe "
                "TQDQuO+Pb6XYiJaUg3LbkAnUSQHawZ6DfAMghevCPTIrTFLTUi8gILIpN2ghfv+z "
                "R2DE2xaKvNzNgEfPxR94haUGZy6eExteWFVbJAbQotux2poksrFqdgTW/7qntrpN "
                "l2AxOYvV/yu0yDjf/kyzt2aoWsbxClNv3jrbAj3m6raY/e6lcr6IuMYWMtO2F3n+ "
                "OzZEXmZyHr121wY= "
                "-----END CERTIFICATE----- "
                "-----BEGIN EC PRIVATE KEY----- "
                "MIGkAgEBBDCUBWVfn8bslTSkoWyA47lB8CwM/R5dlHrH4R52FkCmFFttnlotCt2v "
                "OCzaIX4lCIygBwYFK4EEACKhZANiAARFTRK4qjfOkK25NAssTni1/bKDTvEtmBFy "
                "5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzEREgtGiLBVZ "
                "f8YrYOBPHc93tFiWs7+z1C63uNRUVGs= "
                "-----END EC PRIVATE KEY-----"
            }
        ),
        # - cert and key are in the Certificate section of the Credentials
        # - private key is OpenSSL format
        # *** The cert and key below are not used in the real services, and only used for testing.
        (
            {
                "credentials": {
                    "sshkey": """
-----BEGIN CERTIFICATE-----
MIIDlzCCAX+gAwIBAgIUbN3atZY05K7SilRtY78y2ZON28QwDQYJKoZIhvcNAQEN
BQAwJTEjMCEGA1UEAwwaTWFpbCBMaXN0ZW5lciBUZXN0IFJvb3QgQ0EwHhcNMjMw
NzExMDA1NzI4WhcNMzMwNzExMDA1NzI4WjAaMRgwFgYDVQQDDA90ZXN0IGNsaWVu
dCBlY2MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARFTRK4qjfOkK25NAssTni1/bKD
TvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzERE
gtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGujeDB2MB8GA1UdIwQYMBaAFDh6
N1cbIXsS4uo15Ha9fKZrEbcHMB0GA1UdDgQWBBRFSQMsVOPCmzMbvjnrYMGF1ZNs
8DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggr
BgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAJKmlIV9Du9pnA98vw4GsurAeXU3Y
KlzMyffzIVF+CGTpUFmXIGu1KccZREGQEZpxotYF71HCCqPBUcQD8rRoetxX3wa6
iqk6Q3Pm9Jt8/P365vydvcsKvTEeP8NTWKVip7U8xgAIjykBdnEPu9Uq7x+bePiG
Pqd2Mpzr+mydbU/3mzrZXm/3B0aNiYZdXSpkF4qwZ7lakFvn0MI1M9+B2Am+rNdJ
AoBBQTwS+1pUZoKV3gXMRWKCHj5cbltf1+Lzhh64A8s8k0o1cFyXfSFZ/PJI2rve
ZOKGQ8qIeF3FPCaX5TVvla9J5Mxz5ETXv5zWpK/H4VgPbLf1cZPGFHnYatKkXMvM
05UZ1FmdmJSS8CQQ7AwRsAyWOrbnfUf3Xv5UVFlgGYbsM1+ENbs9Mpn9mq0zq7+J
ONxkmyrkP3Gi/ZK1k9fZuE+WGrnzkP6zUMA76Zr2uH8Gq5Bt89jTl9gAAYuaIDSe
TQDQuO+Pb6XYiJaUg3LbkAnUSQHawZ6DfAMghevCPTIrTFLTUi8gILIpN2ghfv+z
R2DE2xaKvNzNgEfPxR94haUGZy6eExteWFVbJAbQotux2poksrFqdgTW/7qntrpN
l2AxOYvV/yu0yDjf/kyzt2aoWsbxClNv3jrbAj3m6raY/e6lcr6IuMYWMtO2F3n+
OzZEXmZyHr121wY=
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCUBWVfn8bslTSkoWyA47lB8CwM/R5dlHrH4R52FkCmFFttnlotCt2v
OCzaIX4lCIygBwYFK4EEACKhZANiAARFTRK4qjfOkK25NAssTni1/bKDTvEtmBFy
5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzEREgtGiLBVZ
f8YrYOBPHc93tFiWs7+z1C63uNRUVGs=
-----END EC PRIVATE KEY-----
"""
                }
            }
        ),
        # - cert and key are in the integration instance parameters
        # - private key is PKCS#8 PEM
        # *** The cert and key below are not used in the real services, and only used for testing.
        (
            {
                "password": "-----BEGIN CERTIFICATE----- "
                "MIIDlzCCAX+gAwIBAgIUbN3atZY05K7SilRtY78y2ZON28QwDQYJKoZIhvcNAQEN "
                "BQAwJTEjMCEGA1UEAwwaTWFpbCBMaXN0ZW5lciBUZXN0IFJvb3QgQ0EwHhcNMjMw "
                "NzExMDA1NzI4WhcNMzMwNzExMDA1NzI4WjAaMRgwFgYDVQQDDA90ZXN0IGNsaWVu "
                "dCBlY2MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARFTRK4qjfOkK25NAssTni1/bKD "
                "TvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzERE "
                "gtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGujeDB2MB8GA1UdIwQYMBaAFDh6 "
                "N1cbIXsS4uo15Ha9fKZrEbcHMB0GA1UdDgQWBBRFSQMsVOPCmzMbvjnrYMGF1ZNs "
                "8DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggr "
                "BgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAJKmlIV9Du9pnA98vw4GsurAeXU3Y "
                "KlzMyffzIVF+CGTpUFmXIGu1KccZREGQEZpxotYF71HCCqPBUcQD8rRoetxX3wa6 "
                "iqk6Q3Pm9Jt8/P365vydvcsKvTEeP8NTWKVip7U8xgAIjykBdnEPu9Uq7x+bePiG "
                "Pqd2Mpzr+mydbU/3mzrZXm/3B0aNiYZdXSpkF4qwZ7lakFvn0MI1M9+B2Am+rNdJ "
                "AoBBQTwS+1pUZoKV3gXMRWKCHj5cbltf1+Lzhh64A8s8k0o1cFyXfSFZ/PJI2rve "
                "ZOKGQ8qIeF3FPCaX5TVvla9J5Mxz5ETXv5zWpK/H4VgPbLf1cZPGFHnYatKkXMvM "
                "05UZ1FmdmJSS8CQQ7AwRsAyWOrbnfUf3Xv5UVFlgGYbsM1+ENbs9Mpn9mq0zq7+J "
                "ONxkmyrkP3Gi/ZK1k9fZuE+WGrnzkP6zUMA76Zr2uH8Gq5Bt89jTl9gAAYuaIDSe "
                "TQDQuO+Pb6XYiJaUg3LbkAnUSQHawZ6DfAMghevCPTIrTFLTUi8gILIpN2ghfv+z "
                "R2DE2xaKvNzNgEfPxR94haUGZy6eExteWFVbJAbQotux2poksrFqdgTW/7qntrpN "
                "l2AxOYvV/yu0yDjf/kyzt2aoWsbxClNv3jrbAj3m6raY/e6lcr6IuMYWMtO2F3n+ "
                "OzZEXmZyHr121wY= "
                "-----END CERTIFICATE----- "
                "-----BEGIN PRIVATE KEY----- "
                "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCUBWVfn8bslTSkoWyA "
                "47lB8CwM/R5dlHrH4R52FkCmFFttnlotCt2vOCzaIX4lCIyhZANiAARFTRK4qjfO "
                "kK25NAssTni1/bKDTvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHx "
                "dKJkOY6p/VFpzEREgtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGs= "
                "-----END PRIVATE KEY-----"
            }
        ),
        # - cert and key are in the Certificate secion of the Credentials
        # - private key is PKCS#8 PEM
        # *** The cert and key below are not used in the real services, and only used for testing.
        (
            {
                "credentials": {
                    "sshkey": """
-----BEGIN CERTIFICATE-----
MIIDlzCCAX+gAwIBAgIUbN3atZY05K7SilRtY78y2ZON28QwDQYJKoZIhvcNAQEN
BQAwJTEjMCEGA1UEAwwaTWFpbCBMaXN0ZW5lciBUZXN0IFJvb3QgQ0EwHhcNMjMw
NzExMDA1NzI4WhcNMzMwNzExMDA1NzI4WjAaMRgwFgYDVQQDDA90ZXN0IGNsaWVu
dCBlY2MwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARFTRK4qjfOkK25NAssTni1/bKD
TvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHxdKJkOY6p/VFpzERE
gtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGujeDB2MB8GA1UdIwQYMBaAFDh6
N1cbIXsS4uo15Ha9fKZrEbcHMB0GA1UdDgQWBBRFSQMsVOPCmzMbvjnrYMGF1ZNs
8DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggr
BgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAJKmlIV9Du9pnA98vw4GsurAeXU3Y
KlzMyffzIVF+CGTpUFmXIGu1KccZREGQEZpxotYF71HCCqPBUcQD8rRoetxX3wa6
iqk6Q3Pm9Jt8/P365vydvcsKvTEeP8NTWKVip7U8xgAIjykBdnEPu9Uq7x+bePiG
Pqd2Mpzr+mydbU/3mzrZXm/3B0aNiYZdXSpkF4qwZ7lakFvn0MI1M9+B2Am+rNdJ
AoBBQTwS+1pUZoKV3gXMRWKCHj5cbltf1+Lzhh64A8s8k0o1cFyXfSFZ/PJI2rve
ZOKGQ8qIeF3FPCaX5TVvla9J5Mxz5ETXv5zWpK/H4VgPbLf1cZPGFHnYatKkXMvM
05UZ1FmdmJSS8CQQ7AwRsAyWOrbnfUf3Xv5UVFlgGYbsM1+ENbs9Mpn9mq0zq7+J
ONxkmyrkP3Gi/ZK1k9fZuE+WGrnzkP6zUMA76Zr2uH8Gq5Bt89jTl9gAAYuaIDSe
TQDQuO+Pb6XYiJaUg3LbkAnUSQHawZ6DfAMghevCPTIrTFLTUi8gILIpN2ghfv+z
R2DE2xaKvNzNgEfPxR94haUGZy6eExteWFVbJAbQotux2poksrFqdgTW/7qntrpN
l2AxOYvV/yu0yDjf/kyzt2aoWsbxClNv3jrbAj3m6raY/e6lcr6IuMYWMtO2F3n+
OzZEXmZyHr121wY=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCUBWVfn8bslTSkoWyA
47lB8CwM/R5dlHrH4R52FkCmFFttnlotCt2vOCzaIX4lCIyhZANiAARFTRK4qjfO
kK25NAssTni1/bKDTvEtmBFy5N0Qi+kisnUS05e9Okp2d8txhClwbjFbiunaNcHx
dKJkOY6p/VFpzEREgtGiLBVZf8YrYOBPHc93tFiWs7+z1C63uNRUVGs=
-----END PRIVATE KEY-----
"""
                }
            }
        ),
    ],
)
def test_load_client_cert_and_key(mocker, cert_and_key):
    """
    Given:
        Client cetifcates and private keys from the integration's parameters
    When:
        Authenticating the client using SSL client certificate authentication
    Then:
        1. Validate that the SSLContext object, that is used for authentication,
        is given the correct file that holds the certificates
        2. The function 'load_client_cert_and_key' returns True, inidicating that we are using
        SSL client certificate authentication
    """
    from MailListenerV2 import load_client_cert_and_key
    import ssl
    import tempfile

    params = {"clientCertAndKey": cert_and_key}

    named_temporary_file_mocker = mocker.patch(
        "MailListenerV2.NamedTemporaryFile", return_value=tempfile.NamedTemporaryFile(mode="w")
    )
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    load_cert_chain_mocker = mocker.patch.object(ssl_ctx, "load_cert_chain")
    assert load_client_cert_and_key(ssl_ctx, params) is True
    assert load_cert_chain_mocker.call_args_list[0][1].get("certfile") == named_temporary_file_mocker.return_value.name


def test_load_empty_client_cert_and_key_():
    """
    Given:
        Client cetifcates and private keys are not configured in the integration's parameters
    When:
        Authenticating the client
    Then:
        The function 'load_client_cert_and_key' returns False, inidicating that we are not
        using SSL client certificate authentication
    """
    from MailListenerV2 import load_client_cert_and_key
    import ssl

    # - No certificates and private keys
    params: dict[str, dict] = {"clientCertAndKey": {}}

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    assert load_client_cert_and_key(ssl_ctx, params) is False


@pytest.mark.parametrize(
    "input_credentials, output_credentials",
    [
        # No credentials
        (None, None),
        # 1 credential
        (
            "-----BEGIN CERTIFICATE----- " "LINE1 " "LINE2 " "-----END CERTIFICATE-----",
            """-----BEGIN CERTIFICATE-----
LINE1
LINE2
-----END CERTIFICATE-----""",
        ),
        # 2 credentials
        (
            "-----BEGIN CERTIFICATE----- "
            "LINE1 "
            "LINE2 "
            "-----END CERTIFICATE----- "
            "-----BEGIN EC PRIVATE KEY----- "
            "LINE1 "
            "LINE2 "
            "-----END EC PRIVATE KEY-----",
            """-----BEGIN CERTIFICATE-----
LINE1
LINE2
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
LINE1
LINE2
-----END EC PRIVATE KEY-----""",
        ),
        # credentials with human readable text
        (
            "text1 "
            "text2 "
            "-----BEGIN EC PRIVATE KEY----- "
            "LINE1 "
            "LINE2 "
            "-----END EC PRIVATE KEY----- "
            "text1 "
            "text2",
            """text1 text2
-----BEGIN EC PRIVATE KEY-----
LINE1
LINE2
-----END EC PRIVATE KEY-----
text1 text2""",
        ),
    ],
)
def test_replace_spaces_in_credentials(input_credentials, output_credentials):
    """
    Given:
        Client cetifcates and private keys
    When:
        Authenticating the client
    Then:
        Check that the spaces in the credentials are replaced with new lines if they are in the correct format.
    """
    from MailListenerV2 import replace_spaces_in_credentials
    import json

    assert json.dumps(replace_spaces_in_credentials(input_credentials)) == json.dumps(output_credentials)


def test_fetch_incidents__last_uid_as_int(mocker):
    """
    Given:
        - A mock client and last run with 'last_uid' as an integer - 8
    When:
        - Fetching incidents
    Then:
        - Ensure that the "last_uid" received from the 'last_run' of previous cycles is converted to an integer.
        Also, verify that the 'last_uid' to be written in the 'last_run' for the next cycle is a string.
    """
    from MailListenerV2 import fetch_incidents

    mocker.patch("MailListenerV2.Email.convert_to_incident", return_value={})
    fetch_mail_mocker = mocker.patch("MailListenerV2.fetch_mails", return_value=([mock_email()], [mock_email()], 5))

    next_run, _ = fetch_incidents(
        client=mocker.Mock(),
        last_run={"last_uid": 8},
        first_fetch_time="2022-01-01 00:00:00",
        include_raw_body=False,
        with_headers=False,
        permitted_from_addresses="test@example.com",
        permitted_from_domains="example.com",
        delete_processed=False,
        limit=10,
        save_file=False,
    )
    assert isinstance(fetch_mail_mocker.call_args[1]["uid_to_fetch_from"], int)
    assert isinstance(next_run["last_uid"], str)


def test_fetch_incidents__last_uid_as_string(mocker):
    """
    Given:
        - A mock client and last run with 'last_uid' as a string - "8"
    When:
        - Fetching incidents
    Then:
        - Ensure that the "last_uid" received from the 'last_run' of previous cycles is converted to an integer.
        Also, verify that the 'last_uid' to be written in the 'last_run' for the next cycle is a string.
    """
    from MailListenerV2 import fetch_incidents

    mocker.patch("MailListenerV2.Email.convert_to_incident", return_value={})
    fetch_mail_mocker = mocker.patch("MailListenerV2.fetch_mails", return_value=([mock_email()], [mock_email()], 5))

    next_run, _ = fetch_incidents(
        client=mocker.Mock(),
        last_run={"last_uid": "8"},
        first_fetch_time="2022-01-01 00:00:00",
        include_raw_body=False,
        with_headers=False,
        permitted_from_addresses="test@example.com",
        permitted_from_domains="example.com",
        delete_processed=False,
        limit=10,
        save_file=False,
    )
    assert isinstance(fetch_mail_mocker.call_args[1]["uid_to_fetch_from"], int)
    assert isinstance(next_run["last_uid"], str)


def test_fetch_incidents__last_uid_was_zero(mocker):
    """
    Given:
        - A mock client and last run with 'last_uid' as a string - "0"
    When:
        - Fetching incidents
    Then:
        - Ensure that the next run is None, since setting it to "0" will cause an error in the next cycle.

    """
    from MailListenerV2 import fetch_incidents

    mocker.patch("MailListenerV2.Email.convert_to_incident", return_value={})
    mocker.patch("MailListenerV2.fetch_mails", return_value=([mock_email()], [mock_email()], 0))

    next_run, _ = fetch_incidents(
        client=mocker.Mock(),
        last_run={"last_uid": "0"},
        first_fetch_time="2022-01-01 00:00:00",
        include_raw_body=False,
        with_headers=False,
        permitted_from_addresses="test@example.com",
        permitted_from_domains="example.com",
        delete_processed=False,
        limit=10,
        save_file=False,
    )
    assert next_run is None


def test_fetch_mails__mail_id_is_greater(mocker):
    """
    Given:
        - A mock client and last run with uid_to_fetch_from == 2
        - The email UID returend from the client are  [1, 2, 3]
    When:
        - Fetching incidents
    Then:
        - Ensure that next_uid_to_fetch_from is 3 since it is greater than the last run
    """
    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mocker.patch("MailListenerV2.Email")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(IMAPClient, "search", return_value=[1, 2, 3])
    mocker.patch.object(IMAPClient, "fetch")
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    _, _, next_uid_to_fetch_from = fetch_mails(IMAPClient("http://example_url.com"), uid_to_fetch_from=2)
    assert next_uid_to_fetch_from == 3


def test_fetch_mails__last_run_is_greater(mocker):
    """
    Given:
        - A mock client and last run with uid_to_fetch_from == 4
        - The email UID returend from the client are  [1, 2, 3]
    When:
        - Fetching incidents
    Then:
        - Ensure that the next_uid_to_fetch_from is 4 since it is greater than the greatest email UID
    """
    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mocker.patch("MailListenerV2.Email")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(IMAPClient, "search", return_value=[1, 2, 3])
    mocker.patch.object(IMAPClient, "fetch")
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    _, _, next_uid_to_fetch_from = fetch_mails(IMAPClient("http://example_url.com"), uid_to_fetch_from=4)
    assert next_uid_to_fetch_from == 4


def test_fetch_mails__uid_is_str(mocker):
    """
    Given:
        - The email UIDs returend from the client are strings ['1', '2', '3']
    When:
        - Fetching incidents
    Then:
        - Ensure that the next_uid_to_fetch_from is 4 since it is greater than the greatest email UID
    """
    from MailListenerV2 import fetch_mails
    import demistomock as demisto
    from imapclient import IMAPClient

    mocker.patch("MailListenerV2.Email")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(IMAPClient, "search", return_value=["1", "2", "3"])
    mocker.patch.object(IMAPClient, "fetch")
    mocker.patch.object(IMAPClient, "_create_IMAP4")
    _, _, next_uid_to_fetch_from = fetch_mails(IMAPClient("http://example_url.com"), uid_to_fetch_from="4")
    assert next_uid_to_fetch_from == 4
