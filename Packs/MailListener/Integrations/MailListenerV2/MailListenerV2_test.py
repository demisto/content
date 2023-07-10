from datetime import datetime
from freezegun import freeze_time
from tempfile import NamedTemporaryFile
from socketserver import BaseServer, BaseRequestHandler, ThreadingTCPServer
import threading
import socket
import pytest

MAIL_STRING = br"""Delivered-To: to@test1.com
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

MAIL_STRING_NO_DATE = br"""Delivered-To: to@test1.com
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
    {'type': 'Email/from', 'value': 'from@test1.com'},
    {'type': 'Email/format', 'value': 'multipart/alternative'}, {'type': 'Email/text', 'value': ''},
    {'type': 'Email/subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/Delivered-To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/MIME-Version', 'value': '1.0'},
    {'type': 'Email/headers/From', 'value': 'John Smith <from@test1.com>'},
    {'type': 'Email/headers/Date', 'value': 'Mon, 10 Aug 2020 10:17:16 +0300'},
    {'type': 'Email/headers/Subject', 'value': 'Testing email for mail listener'},
    {'type': 'Email/headers/To', 'value': 'to@test1.com'},
    {'type': 'Email/headers/Content-Type',
     'value': 'multipart/alternative; boundary="0000000000002b271405ac80bf8b"'},
    {'type': 'Email', 'value': 'to@test1.com'},
    {'type': 'Email/html', 'value': '<div dir="ltr"><br></div>\n<p>C:\\\\Users</p>\n<p>C:\\\\Users</p>'}]


@freeze_time("2022-12-11 13:40:00 UTC")
@pytest.mark.parametrize('mail_string, mail_date',
                         [(MAIL_STRING, '2020-08-10T07:17:16+00:00'),
                          (MAIL_STRING_NO_DATE, "2022-12-11T13:40:00+00:00")])
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
    assert incident['occurred'] == mail_date
    assert incident['details'] == email.text or email.html
    assert incident['name'] == email.subject


@pytest.mark.parametrize(
    'time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from, expected_query',
    # noqa: E501
    [
        (
                datetime(year=2020, month=10, day=1),  # noqa: E126
                False,  # noqa: E126
                ['test1@mail.com', 'test2@mail.com'],
                ['test1.com', 'domain2.com'],
                4,
                [
                    'OR',
                    'OR',
                    'OR',
                    'FROM',
                    'domain2.com',
                    'FROM',
                    'test1.com',
                    'FROM',
                    'test1@mail.com',
                    'FROM',
                    'test2@mail.com',
                    'SINCE',
                    datetime(year=2020, month=10, day=1),
                    'UID',
                    '4:*'
                ]
        ),
        (
                datetime(year=2020, month=10, day=1),  # noqa: E126
                True,  # noqa: E126
                ['test1@mail.com', 'test2@mail.com'],
                ['test1.com', 'domain2.com'],
                4,
                [
                    'OR',
                    'OR',
                    'OR',
                    'HEADER',
                    'FROM',
                    'domain2.com',
                    'HEADER',
                    'FROM',
                    'test1.com',
                    'HEADER',
                    'FROM',
                    'test1@mail.com',
                    'HEADER',
                    'FROM',
                    'test2@mail.com',
                    'SINCE',
                    datetime(year=2020, month=10, day=1),
                    'UID',
                    '4:*'
                ]
        ),
        (
                None,  # noqa: E126
                '',  # noqa: E126
                [],
                [],
                1,
                [
                    'UID',
                    '1:*'
                ]
        )
    ]
)
def test_generate_search_query(
        time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from,
        expected_query
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
    assert generate_search_query(
        time_to_fetch_from, with_header, permitted_from_addresses, permitted_from_domains, uid_to_fetch_from
    ) == expected_query


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
        assert label in labels, f'Label {label} was not found in the generated labels, {labels}'


def mock_email():
    from unittest.mock import patch
    from MailListenerV2 import Email
    with patch.object(Email, '__init__', lambda a, b, c, d, e: None):
        email = Email('data', False, False, 0)
        email.id = 0
        email.date = 0
        return email


@pytest.mark.parametrize('src_data, expected', [({1: {b'RFC822': br'C:\User\u'}}, br'C:\User\u'),
                                                ({2: {b'RFC822': br'C:\User\u'}}, br'C:\User\u')])
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

    mail_mocker = mocker.patch('MailListenerV2.Email', return_value=mock_email())
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(IMAPClient, 'search')
    mocker.patch.object(IMAPClient, 'fetch', return_value=src_data)
    mocker.patch.object(IMAPClient, '_create_IMAP4')
    fetch_mails(IMAPClient('http://example_url.com'))
    assert mail_mocker.call_args[0][0] == expected


def test_get_eml_attachments():
    from MailListenerV2 import Email
    import email
    # Test an email with a PNG attachment
    with open(
            'test_data/eml-with-jpeg.eml', "rb") as f:
        msg = email.message_from_bytes(f.read())
    res = Email.get_eml_attachments(msg.as_bytes())
    assert res == []
    # Test an email with EML attachment
    with open(
            'test_data/eml-with-eml-with-attachment.eml', "rb") as f:
        msg = email.message_from_bytes(f.read())
    res = Email.get_eml_attachments(msg.as_bytes())
    assert res[0]['filename'] == 'Test with an image.eml'


@pytest.mark.parametrize('cert_and_key, ok', [
    # - No certificates and private keys
    ({
    },
        False
    ),
    # - cert and key are in the integration instance parameters
    # - private key is OpenSSL format
    # *** The cert and key below are not used in the real services, and only used for testing.
    ({
        'password': '-----BEGIN CERTIFICATE----- '\
                    'MIICgjCCAWqgAwIBAgIUM5F15oX3zziMmqTnOwcLSW6ov2swDQYJKoZIhvcNAQEL '\
                    'BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0yMzA3MDQwNTM0MDBa '\
                    'Fw0zMzA3MDQwNTM0MDBaMA8xDTALBgNVBAMMBHRlc3QwdjAQBgcqhkjOPQIBBgUr '\
                    'gQQAIgNiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737 '\
                    'kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5K '\
                    'fxZV0LhVY2ajeDB2MB8GA1UdIwQYMBaAFNlAepeklNOL3TdmkIc/rr7nnCEJMB0G '\
                    'A1UdDgQWBBRQnkuPLTi8KfGdecmzD8koLvF2CzAMBgNVHRMBAf8EAjAAMA4GA1Ud '\
                    'DwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF '\
                    'AAOCAQEADzI0kHdyb4tAnCCdN+xem8EimwEFbGgep5XME+gw9fS6kixdjjH0lJvM '\
                    'Y7e+v6qeB7CpTSp0Kowy20QIGbdvu9IdyDdeHSCWizhdcZQCUbqfFyXWGu3Hjr+a '\
                    'XfYYgUEffLvr5JXX6vA517Y+qd+s52snq5xwLcwAlhSyn/cAERmeZiyXdSxJ5GKW '\
                    '0lg5nwFneCcUH7w12UzcsOHPbw+O0kcZSOJ1X9dXfGJbbjH2ehP04c1yC6xznHBo '\
                    '5gXmyCLQyhWzx9evMfzSqsYEDnldlfuU2udB+l6gnmsAxmX6HxyypzKEK4EtupyM '\
                    'UAKOO0ZKW6fY7dXbiOtc5VWFrY2qmQ== '\
                    '-----END CERTIFICATE----- '\
                    '-----BEGIN EC PRIVATE KEY----- '\
                    'MIGkAgEBBDCmOdUkhzeHqGnwZSnXyFa42iW6IF4X9TfLcq1t48ZU7zOJDfRQp4fa '\
                    'E/W0C/0vmK+gBwYFK4EEACKhZANiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/ '\
                    'MGhSAOsYkk8+ApA4n737kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh '\
                    '255HhF8ItlZoKxSCn/5KfxZV0LhVY2Y= '\
                    '-----END EC PRIVATE KEY-----'
    },
        True
    ),
    # - cert and key are in the Certificate secion of the Credentials
    # - private key is OpenSSL format
    # *** The cert and key below are not used in the real services, and only used for testing.
    ({
        'credentials': {
            'sshkey': '''
-----BEGIN CERTIFICATE-----
MIICgjCCAWqgAwIBAgIUM5F15oX3zziMmqTnOwcLSW6ov2swDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0yMzA3MDQwNTM0MDBa
Fw0zMzA3MDQwNTM0MDBaMA8xDTALBgNVBAMMBHRlc3QwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737
kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5K
fxZV0LhVY2ajeDB2MB8GA1UdIwQYMBaAFNlAepeklNOL3TdmkIc/rr7nnCEJMB0G
A1UdDgQWBBRQnkuPLTi8KfGdecmzD8koLvF2CzAMBgNVHRMBAf8EAjAAMA4GA1Ud
DwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF
AAOCAQEADzI0kHdyb4tAnCCdN+xem8EimwEFbGgep5XME+gw9fS6kixdjjH0lJvM
Y7e+v6qeB7CpTSp0Kowy20QIGbdvu9IdyDdeHSCWizhdcZQCUbqfFyXWGu3Hjr+a
XfYYgUEffLvr5JXX6vA517Y+qd+s52snq5xwLcwAlhSyn/cAERmeZiyXdSxJ5GKW
0lg5nwFneCcUH7w12UzcsOHPbw+O0kcZSOJ1X9dXfGJbbjH2ehP04c1yC6xznHBo
5gXmyCLQyhWzx9evMfzSqsYEDnldlfuU2udB+l6gnmsAxmX6HxyypzKEK4EtupyM
UAKOO0ZKW6fY7dXbiOtc5VWFrY2qmQ==
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCmOdUkhzeHqGnwZSnXyFa42iW6IF4X9TfLcq1t48ZU7zOJDfRQp4fa
E/W0C/0vmK+gBwYFK4EEACKhZANiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/
MGhSAOsYkk8+ApA4n737kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh
255HhF8ItlZoKxSCn/5KfxZV0LhVY2Y=
-----END EC PRIVATE KEY-----
'''
        }
    },
        True
    ),
    # - cert and key are in the integration instance parameters
    # - private key is PKCS#8 PEM
    # *** The cert and key below are not used in the real services, and only used for testing.
    ({
        'password': '-----BEGIN CERTIFICATE----- '\
                    'MIICgjCCAWqgAwIBAgIUM5F15oX3zziMmqTnOwcLSW6ov2swDQYJKoZIhvcNAQEL '\
                    'BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0yMzA3MDQwNTM0MDBa '\
                    'Fw0zMzA3MDQwNTM0MDBaMA8xDTALBgNVBAMMBHRlc3QwdjAQBgcqhkjOPQIBBgUr '\
                    'gQQAIgNiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737 '\
                    'kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5K '\
                    'fxZV0LhVY2ajeDB2MB8GA1UdIwQYMBaAFNlAepeklNOL3TdmkIc/rr7nnCEJMB0G '\
                    'A1UdDgQWBBRQnkuPLTi8KfGdecmzD8koLvF2CzAMBgNVHRMBAf8EAjAAMA4GA1Ud '\
                    'DwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF '\
                    'AAOCAQEADzI0kHdyb4tAnCCdN+xem8EimwEFbGgep5XME+gw9fS6kixdjjH0lJvM '\
                    'Y7e+v6qeB7CpTSp0Kowy20QIGbdvu9IdyDdeHSCWizhdcZQCUbqfFyXWGu3Hjr+a '\
                    'XfYYgUEffLvr5JXX6vA517Y+qd+s52snq5xwLcwAlhSyn/cAERmeZiyXdSxJ5GKW '\
                    '0lg5nwFneCcUH7w12UzcsOHPbw+O0kcZSOJ1X9dXfGJbbjH2ehP04c1yC6xznHBo '\
                    '5gXmyCLQyhWzx9evMfzSqsYEDnldlfuU2udB+l6gnmsAxmX6HxyypzKEK4EtupyM '\
                    'UAKOO0ZKW6fY7dXbiOtc5VWFrY2qmQ== '\
                    '-----END CERTIFICATE----- '\
                    '-----BEGIN PRIVATE KEY----- '\
                    'MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCmOdUkhzeHqGnwZSnX '\
                    'yFa42iW6IF4X9TfLcq1t48ZU7zOJDfRQp4faE/W0C/0vmK+hZANiAAQ2iJqs8Ca+ '\
                    'FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737kWtSdolGPfjjxaHvFBcu '\
                    'rCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5KfxZV0LhVY2Y= '\
                    '-----END PRIVATE KEY-----'
    },
        True
    ),
    # - cert and key are in the Certificate secion of the Credentials
    # - private key is PKCS#8 PEM
    # *** The cert and key below are not used in the real services, and only used for testing.
    ({
        'credentials': {
            'sshkey': '''
-----BEGIN CERTIFICATE-----
MIICgjCCAWqgAwIBAgIUM5F15oX3zziMmqTnOwcLSW6ov2swDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0yMzA3MDQwNTM0MDBa
Fw0zMzA3MDQwNTM0MDBaMA8xDTALBgNVBAMMBHRlc3QwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAAQ2iJqs8Ca+FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737
kWtSdolGPfjjxaHvFBcurCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5K
fxZV0LhVY2ajeDB2MB8GA1UdIwQYMBaAFNlAepeklNOL3TdmkIc/rr7nnCEJMB0G
A1UdDgQWBBRQnkuPLTi8KfGdecmzD8koLvF2CzAMBgNVHRMBAf8EAjAAMA4GA1Ud
DwEB/wQEAwIE8DAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsF
AAOCAQEADzI0kHdyb4tAnCCdN+xem8EimwEFbGgep5XME+gw9fS6kixdjjH0lJvM
Y7e+v6qeB7CpTSp0Kowy20QIGbdvu9IdyDdeHSCWizhdcZQCUbqfFyXWGu3Hjr+a
XfYYgUEffLvr5JXX6vA517Y+qd+s52snq5xwLcwAlhSyn/cAERmeZiyXdSxJ5GKW
0lg5nwFneCcUH7w12UzcsOHPbw+O0kcZSOJ1X9dXfGJbbjH2ehP04c1yC6xznHBo
5gXmyCLQyhWzx9evMfzSqsYEDnldlfuU2udB+l6gnmsAxmX6HxyypzKEK4EtupyM
UAKOO0ZKW6fY7dXbiOtc5VWFrY2qmQ==
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCmOdUkhzeHqGnwZSnX
yFa42iW6IF4X9TfLcq1t48ZU7zOJDfRQp4faE/W0C/0vmK+hZANiAAQ2iJqs8Ca+
FRxOF7c3atmzVXZ19BXSII2/MGhSAOsYkk8+ApA4n737kWtSdolGPfjjxaHvFBcu
rCjrSCXfje8zVD39AneXN2Uh255HhF8ItlZoKxSCn/5KfxZV0LhVY2Y=
-----END PRIVATE KEY-----
'''
        }
    },
        True
    )
])
def test_load_client_cert_and_key(cert_and_key, ok):
    from MailListenerV2 import load_client_cert_and_key
    import ssl

    params = {
        'clientCertAndKey': cert_and_key
    }
    ssl_ctx = ssl.create_default_context()
    assert (load_client_cert_and_key(ssl_ctx, params) == ok)

    def _test_connect(ssl_client_ctx: ssl.SSLContext):
        class TestSSLServer(BaseRequestHandler):
            def __init__(
                self,
                request,
                client_address,
                server
            ) -> None:
                self.__ssl_server_context: ssl.SSLContext = None  # type: ignore
                BaseRequestHandler.__init__(self, request, client_address, server)

            def setup(self) -> None:
                self.__ssl_server_context = self.server.ssl_server_ctx

            def handle(self) -> None:
                try:
                    with self.__ssl_server_context.wrap_socket(
                            self.request,
                            server_side=True,
                            do_handshake_on_connect=False) as s:
                        s.do_handshake()
                finally:
                    self.request.close()

        # *** The cert and key below are not used in the real services, and only used for testing.
        server_cert_and_key = '''
-----BEGIN CERTIFICATE-----
MIICpDCCAYygAwIBAgIUXAXF05FBOj9RwqAj8FN92fdqh3gwDQYJKoZIhvcNAQEN
BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0yMzA3MTAxNTUzNTFa
Fw0zOTA4MDMxNTQxNTVaMBUxEzARBgNVBAMMCnRlc3QubG9jYWwwdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAASx1e+Sl/kzvpaCon8C92vLw9/tBBvI4tQFD8lahBcbTakD
d0XatOS0F9ko6knJYl4rkXaKLqf3d8ZhbJOfAa9Xyo7Sm9c7xldpdUr/eOWGpZAA
SbGw7FWSDF4waFmIktajgZMwgZAwHwYDVR0jBBgwFoAU2UB6l6SU04vdN2aQhz+u
vuecIQkwHQYDVR0OBBYEFA3dejB46+/wnw3Q+AW1oRHCW/umMAwGA1UdEwEB/wQC
MAAwDgYDVR0PAQH/BAQDAgWgMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMBgGA1Ud
EQEB/wQOMAyCCnRlc3QubG9jYWwwDQYJKoZIhvcNAQENBQADggEBAHMzaK5mDINh
oMZVp/BjuV0TKFv/4zpEpRBPLl2LOnnTaBKxKUM6MdJ0Qv5MGR6PdGKnFQw+pvSX
EFAlxgBkC785bUcXA9WXxVCjHQGcgyNU5YQRi05jWzHkZEkg/3034zR4QOnJIIPw
vAxq8RbwfFp94X68MsQsX9g3jm0u6LPoMJSRKuL6yL7dhl19CUKBiposPlru1zJm
fCIumvOZ+FPwXC2t3c+KhZzAH7c3tonWuMCQR7t+kGN0oqFpzLsn7U87xSlWmMLM
E4j+t9oEzuqrSRIob/GblUVyfyKnNOrN7AqneLl4pwwxYwQIFDxtEy3Pp5YGgi6f
52XOlZ+PYwU=
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCSBZzgrQHM+YoRQBA/PjvO2l/fUyuG/DGnIqS4kvy+u6AIDAP02Dvd
ykxovJvA1o2gBwYFK4EEACKhZANiAASx1e+Sl/kzvpaCon8C92vLw9/tBBvI4tQF
D8lahBcbTakDd0XatOS0F9ko6knJYl4rkXaKLqf3d8ZhbJOfAa9Xyo7Sm9c7xldp
dUr/eOWGpZAASbGw7FWSDF4waFmIktY=
-----END EC PRIVATE KEY-----
                      '''

        # *** The cert below is not used in the real services, and only used for testing.
        ca_cert = '''
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUALYDuYO2fKF7dhWhtCbNP2o50QwwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAxMQRGVmYXVsdCBMb2NhbCBDQTAeFw0xOTA4MDMxNTQxNTVa
Fw0zOTA4MDMxNTQxNTVaMBsxGTAXBgNVBAMTEERlZmF1bHQgTG9jYWwgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCNEjdhN6HmpwN2fQC2oTkhSL3W
5O/gSqi08Q8I4gjAA0+F1x7ZsBHkoGeCulNX+s4Auq6O18oEWAXW0nzLALOclcnD
OyhM6hnQ+vjNRohPwYdUCvjHDHEKGY2uPo2irIpjzANC5b/9VdPY+7wM1zp+u4M4
725w5x1SUgnceWuKVbemKAKESdAhS/edVXU7IfXNZf29fIhPpizW5Wb7ikcDnNXj
G1l7l6n5Lix6YTSnty9TEsNta6lu8r4SuQ6KTIyOnRUdKPFuFQGKdelm0FJDwaGu
tvPXgJmaEoU4hKdk3ER2Df5ZcpHlu3dVCjrzE9YC7/GTr1Uz/R+gwsAoZDz3AgMB
AAGjYzBhMB8GA1UdIwQYMBaAFNlAepeklNOL3TdmkIc/rr7nnCEJMB0GA1UdDgQW
BBTZQHqXpJTTi903ZpCHP66+55whCTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAZ3H+OWFq8Ov7XU3QqaqM0xPSLJ4L
iswrHnQyS6Dss/e5tGYOzlk+LsagyiHzMTDzqlh9/97Pl7U5MGhcrS+fXI0JboEv
hw2+2wTCesXhOnSdJ8fxU6LCQuPPjtzNKMKlES9GzPCI2VIFwjYWGnTagGtJK6mL
2DtpqT1YMClLvZam5nyS/tZfq2KVV7QV5buWJSYLv8mHiG9MESzVy5aax++u+g/s
vVMJGGpbfQnTdas34BHVKtJybZxjLIWA+IgFocIwsMaTu8yRGmLq/JgeMfHyTAGn
iZhq9FgKdJIJrHzg6onTh6uSkeg378q2DOfxyL6hKIl89o4iUyqHM6cJSA==
-----END CERTIFICATE-----
                  '''

        ssl_client_ctx.check_hostname = False
        ssl_client_ctx.verify_mode = ssl.CERT_NONE

        ssl_server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_server_ctx.verify_mode = ssl.CERT_REQUIRED
        with NamedTemporaryFile(mode='w') as f:
            f.write(server_cert_and_key)
            f.flush()
            f.seek(0)
            ssl_server_ctx.load_cert_chain(certfile=f.name, keyfile=None)

        with NamedTemporaryFile(mode='w') as f:
            f.write(ca_cert)
            f.flush()
            f.seek(0)
            ssl_server_ctx.load_verify_locations(cafile=f.name)

        with ThreadingTCPServer(('', 0), TestSSLServer) as server:
            server.ssl_server_ctx = ssl_server_ctx
            server_ip, server_port = server.socket.getsockname()

            def _serve_forever(server: BaseServer) -> None:
                server.serve_forever()

            thr = threading.Thread(target=_serve_forever, args=(server,), daemon=False)
            thr.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, \
                     ssl_client_ctx.wrap_socket(s, server_side=False) as ss:
                    ss.connect((server_ip, server_port))
            finally:
                server.shutdown()
                thr.join()

    if ok:
        _test_connect(ssl_ctx)
