from ExtractEmail import verify_is_email, main
import pytest
import demistomock as demisto

# Bitcoin address, expected_output
testdata = [
    ('Xsoar@test.org.de', True),
    ('Xsoar@test.uk', True),
    ('Xsoar@test.uk.Png', False),
    ('Xsoar@test.pNG', False),
    ('Xsoar@test.new.Docx', False),
    ('entry@id.com.GIF', False),
    ('Xsoar@test.com', True),
    ('Xsoar@test.BmP', False),
    ('Xsoa r@ test.BmP', False),
]


@pytest.mark.parametrize('address,valid', testdata)
def test_verify_is_email(address, valid):
    """Verifies that email address that was auto-extracted via the Email regex is valid.
    Given
    - address.
    When
    - When there is an address that looks like a bitcoin address.
    Then
    - Checks if it's a bitcoin address or not
    """
    assert verify_is_email(address) is valid


ARGS = {
    'input': 'Xsoar@test.org.de, Xsoar@test.uk, Xsoar@xsoar.xlsx,Xsoar@xsoar.co.il,Xsoar@xsoar.bla.test'}
EXPECTED_RESULTS = ['Xsoar@test.org.de', 'Xsoar@test.uk', 'Xsoar@xsoar.co.il', 'Xsoar@xsoar.bla.test']


def test_main(mocker):
    """Verifies that all valid addresses get returned.
       Given
       - addresses.
       When
       - When there are multiple addresses that looks like a bitcoin address.
       Then
       - Return all valid addresses
       """
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(demisto, 'results')
    main()
    assert EXPECTED_RESULTS == demisto.results.call_args[0][0]
