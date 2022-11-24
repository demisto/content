from ExtractEmailFormatting import main, check_tld, extract_email, refang_email
import pytest
import demistomock as demisto


defang_data = [
    ('xsoar@test[.]com', 'xsoar@test.com'),
    ('xsoar[@]test[.]com', 'xsoar@test.com'),
    ('xsoar[@]test.com', 'xsoar@test.com'),
]


@pytest.mark.parametrize('address,valid', defang_data)
def test_check_defanging(address, valid):
    assert refang_email(address) == valid


tld_data = [
    ('Xsoar@test.org.de', True),
    ('xsoar@test.net.bla', True),
    ('Xsoar@test.uk.png', False),
    ('Xsoar@test.eml', False),
    ('Xsoar@test.new.docx', False),
    ('entry@id.com.gif', False),
    ('randomName@randomDomain.com', True),
    ('Xsoar@xsoar.xlsx', False),
]


@pytest.mark.parametrize('address,valid', tld_data)
def test_check_tld(address, valid):
    assert check_tld(address) is valid


@pytest.mark.parametrize('input,output', [  # noqa: E501 disable-secrets-detection # no processing needed
    ('\\u003ctest@test.com', 'test@test.com'),
    ('"test@test.com"', 'test@test.com'),
    ('<test@test.com>', 'test@test.com'),
])  # noqa: E124
def test_extract_email(input, output):
    assert extract_email(input) == output


ARGS = {
    'input': 'Xsoar@test.org.de,Xsoar@test.eml, Xsoar@test.uk, Xsoar@xsoar.xlsx,Xsoar@xsoar.co.il'
}

EXPECTED_RESULTS = [
    'xsoar@test.org.de',
    '',
    'xsoar@test.uk',
    '',
    'xsoar@xsoar.co.il',
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
    assert EXPECTED_RESULTS == demisto.results.call_args[0][0]


def test_main_invalid_emails(mocker):
    """Verifies that no input returns an empty string.
       Given
       - Empty string as an input to the fprmatter.
       When
       - An empty string is passed to formatter by the user.
       Then
       - Return an empty string
       """
    mocker.patch.object(demisto, 'args', return_value={"input": ''})
    mocker.patch.object(demisto, 'results')
    main()
    assert '' == demisto.results.call_args[0][0]
