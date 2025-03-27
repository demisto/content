from CheckEmailAuthenticity import main, get_authentication_value, get_spf
import demistomock as demisto

MOCK_HEADERS = [
    {
        'name': 'Message-ID',
        'value': 'test_message_id'
    },
    {
        'name': 'received-spf',
        'value': 'Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)'
                 'receiver=test.com; client-ip=8.8.8.8; helo=test.com;'
    },
    {
        'name': 'Authentication-Results',
        'value': 'spf=pass (sender IP is 8.8.8.8) smtp.mailfrom=test.com; dkim=fail (body hash did not verify) '
                 'header.d=test.com; dmarc=pass action=none header.from=test.com;compauth=pass reason=100'
    }
]

MOCK_HEADERS_DIFFERENT_AUTH_HEADER = [
    {
        'name': 'Message-ID',
        'value': 'test_message_id'
    },
    {
        'name': 'received-spf',
        'value': 'Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)'
                 'receiver=test.com; client-ip=8.8.8.8; helo=test.com;'
    },
    {
        'name': 'Authentication-Results',
        'value': 'mock_different_value'
    }
]

EMAIL_KEY = "Email(val.Headers.filter(function(header) { return header && header.name === \'Message-ID\' && " \
            "header.value === \'test_message_id\';}))"


def test_check_email_auth(mocker):
    mocker.patch.object(demisto, 'args', return_value={'headers': MOCK_HEADERS})
    mocker.patch.object(demisto, 'results')

    main()

    results = demisto.results.call_args[0]

    # assert (str(results[0]['EntryContext'])) == '3'

    dmarc = results[0]['EntryContext']['{}.DMARC'.format(EMAIL_KEY)]
    assert dmarc['Validation-Result'] == 'pass'
    assert dmarc['Signing-Domain'] == 'test.com'

    spf = results[0]['EntryContext']['{}.SPF'.format(EMAIL_KEY)]
    assert spf['Validation-Result'] == 'pass'
    assert spf['Sender-IP'] == '8.8.8.8'

    dkim = results[0]['EntryContext']['{}.DKIM'.format(EMAIL_KEY)]
    assert dkim['Validation-Result'] == 'fail'
    assert dkim['Reason'] == 'body hash did not verify'

    # AuthenticityCheck fails because DKIM failed
    assert results[0]['EntryContext']['{}.AuthenticityCheck'.format(EMAIL_KEY)] == 'Fail'


def test_get_authentication_value():
    """
    Given:
        an authenticator header that is not a part of the given headers array.
    When:
        there is an intermediate server which changes the email and holds the original value of the header in a
        different header.
    Then:
        override the given authenticator headers in the headers array and use the original one.
    """

    original_authentication_header_included_in_headers = 'Authentication-Results'
    original_authentication_header_not_included_in_headers = 'Authentication-Results-Not-Included'

    assert get_authentication_value(MOCK_HEADERS_DIFFERENT_AUTH_HEADER,
                                    original_authentication_header_not_included_in_headers) == 'mock_different_value'
    assert get_authentication_value(MOCK_HEADERS, original_authentication_header_included_in_headers) \
        == 'spf=pass (sender IP is 8.8.8.8) smtp.mailfrom=test.com; dkim=fail (body hash did not verify) ' \
        'header.d=test.com; dmarc=pass action=none header.from=test.com;compauth=pass reason=100'


def test_get_spf_formats():
    spf_with_parentheses = 'Pass (test.com: domain of test.com designates 8.8.8.8 as permitted sender)'
    spf_without_parentheses = 'Pass test.com: domain of test.com designates 8.8.8.8 as permitted sender'

    spf_data = get_spf(auth=None, spf=spf_with_parentheses)
    assert spf_data['Validation-Result'] == 'pass'
    assert spf_data['Sender-IP'] == '8.8.8.8'

    spf_data = get_spf(auth=None, spf=spf_without_parentheses)
    assert spf_data['Validation-Result'] == 'pass'
    assert spf_data['Sender-IP'] == '8.8.8.8'
