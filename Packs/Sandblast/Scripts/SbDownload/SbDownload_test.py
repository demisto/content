import pytest
import SbDownload


def test_main(mocker):
    """
    Given:
    -   Ips in a string

    When:
    -   Convetting them to an ip list.

    Then:
    - Ensure that the list we get is what we expected.
    """

    assert SbDownload.main == expected
