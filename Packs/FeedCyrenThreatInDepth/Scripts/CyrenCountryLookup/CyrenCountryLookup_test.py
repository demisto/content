import pytest


@pytest.mark.parametrize("value, expected", [
    ("DE", "Germany"),
    ("de", "Germany"),
    ("De", "Germany"),
    ("ZZ", "ZZ"),
    ("Zz", "Zz"),
])
def test_lookup(value, expected):
    """
    Given: Different arg input
    When: Running lookup command.
    Then: either the correct country name will be returned or the code itself if no match
    """
    from CyrenCountryLookup import lookup

    assert lookup(dict(value=value)) == expected


@pytest.mark.parametrize("args", [
    dict(),
    dict(value=None),
    dict(value=""),
    dict(value=9),
    dict(value=[]),
])
def test_lookup_error(args):
    """
    Given: Different arg input
    When: Running lookup command on invalid values
    Then: will raise an exception
    """
    from CyrenCountryLookup import lookup

    with pytest.raises(Exception):
        lookup(args)
