from CheckEmailAuthenticity import main
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
