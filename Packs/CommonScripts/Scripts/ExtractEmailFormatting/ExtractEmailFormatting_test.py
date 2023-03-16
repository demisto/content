from ExtractEmailFormatting import main, check_tld, extract_email, refang_email, extract_email_from_url_query
import pytest
import demistomock as demisto


defang_data = [
    ('xsoar@test[.]com', 'xsoar@test.com'),  # disable-secrets-detection
    ('xsoar[@]test[.]com', 'xsoar@test.com'),  # disable-secrets-detection
    ('xsoar[@]test.com', 'xsoar@test.com'),  # disable-secrets-detection
]


@pytest.mark.parametrize('address,valid', defang_data)
def test_check_defanging(address, valid):
    assert refang_email(address) == valid


tld_data = [
    ('Xsoar@test.org.de', True),  # disable-secrets-detection
    ('xsoar@test.net.bla', True),  # disable-secrets-detection
    ('Xsoar@test.uk.png', False),  # disable-secrets-detection
    ('Xsoar@test.eml', False),  # disable-secrets-detection
    ('Xsoar@test.new.docx', False),  # disable-secrets-detection
    ('entry@id.com.gif', False),  # disable-secrets-detection
    ('randomName@randomDomain.com', True),  # disable-secrets-detection
    ('Xsoar@xsoar.xlsx', False),  # disable-secrets-detection
]


@pytest.mark.parametrize('address,valid', tld_data)
def test_check_tld(address, valid):
    assert check_tld(address) is valid


@pytest.mark.parametrize('input,output', [  # noqa: E501 disable-secrets-detection # no processing needed
    ('\\u003ctest@test.com', 'test@test.com'),
    ('"test@test.com"', 'test@test.com'),
    ('<test@test.com>', 'test@test.com'),
    ('test', ''),
    ('co/ed/trn/update?a=b&email=user@test6.net', 'user@test6.net'),
])  # noqa: E124
def test_extract_email(input, output):
    assert extract_email(input) == output


@pytest.mark.parametrize('input,output', [  # noqa: E501 disable-secrets-detection # no processing needed
    ('co/ed/trn/update?a=b&email=user@test6.net', 'user@test6.net'),
    ('co/ed/trn/update?', ''),
])  # noqa: E124
def test_extract_email_from_url_query(input, output):
    assert extract_email_from_url_query(input) == output


ARGS = {
    'input': 'Xsoar@test.org.de,Xsoar@test.eml, '  # disable-secrets-detection
             'Xsoar@test.uk, '  # disable-secrets-detection
             'Xsoar@xsoar.xlsx,Xsoar@xsoar.co.il'  # disable-secrets-detection
}

EXPECTED_RESULTS = [
    ['xsoar@test.org.de'],  # disable-secrets-detection
    [],
    ['xsoar@test.uk'],  # disable-secrets-detection
    [],
    ['xsoar@xsoar.co.il'],  # disable-secrets-detection
]


def test_main(mocker):
    """Verifies that all valid addresses get returned.
       Given
       - Email addresses that were auto-extracted by the Email regex.
       When
       - Auto extracting an email address or using the extractIndicator script.
       Then
       - Return all valid addresses
       """
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(demisto, 'results')
    main()
    results = [email_address['Contents'] for email_address in demisto.results.call_args[0][0]]
    assert EXPECTED_RESULTS == results


def test_main_invalid_emails(mocker):
    """Verifies that no input returns an empty string.
       Given
       - Empty string as an input to the formatter.
       When
       - An empty string is passed to formatter by the user.
       Then
       - Return an empty string
       """
    mocker.patch.object(demisto, 'args', return_value={"input": ''})
    mocker.patch.object(demisto, 'results')
    main()
    assert '' == demisto.results.call_args[0][0]
