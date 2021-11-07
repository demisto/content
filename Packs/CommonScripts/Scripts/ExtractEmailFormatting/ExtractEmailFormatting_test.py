from ExtractEmailFormatting import verify_is_email, main
import pytest
import demistomock as demisto

testdata = [
    ('Xsoar@test.org.de', True),
    ('xsoar@test.net.bla', True),
    ('Xsoar@test.uk.Png', False),
    ('Xsoar@test.eml', False),
    ('Xsoar@test.new.Docx', False),
    ('entry@id.com.gif', False),
    ('randomName@randomDomain.com', True),
    ('Xsoar@xsoar.xlsx', False),
    ('Xsoa r@ test.BmP', False),
    ('bt53h6htyj8j57k9k=organization.org@ozzy.qwer.de', True),
    ('Xsoar[@]test.org.de', True),
    ('xsoar[@]test.net.bla', True),
    ('Xsoar[@]test.uk.Png', False),
    ('Xsoar[@]test.eml', False),
    ('Xsoar[@]test.new.Docx', False),
    ('entry[@]id.com.gif', False),
    ('randomName[@]randomDomain.com', True),
    ('Xsoar[@]xsoar.xlsx', False),
    ('Xsoa r[@] test.BmP', False),
    ('bt53h6htyj8j57k9k=organization.org[@]ozzy.qwer.de', True),
]


@pytest.mark.parametrize('address,valid', testdata)
def test_verify_is_email(address, valid):
    """Verifies that email address that was auto-extracted via the Email regex is valid.
    Given
    - address.
    When
    - When an email address was auto-extracted
    Then
    - Checks if it's an email address or not
    """
    assert verify_is_email(address) is valid


ARGS = {
    'input': 'Xsoar@test.org.de,Xsoar@test.eml, Xsoar@test.uk, Xsoar@xsoar.xlsx,Xsoar@xsoar.co.il'}
EXPECTED_RESULTS = ['Xsoar@test.org.de', 'Xsoar@test.uk', 'Xsoar@xsoar.co.il']


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
