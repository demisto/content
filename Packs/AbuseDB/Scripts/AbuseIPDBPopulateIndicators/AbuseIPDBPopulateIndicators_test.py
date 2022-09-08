import pytest

from CommonServerPython import DemistoException


def test_get_contents():
    from AbuseIPDBPopulateIndicators import get_contents

    assert get_contents({}) is None


@pytest.mark.parametrize("input", ["Too many requests", None])
def test_check_ips_fail(input):
    from AbuseIPDBPopulateIndicators import check_ips

    with pytest.raises(DemistoException) as e:
        check_ips(input)
    assert str(e.value) == "No Indicators were created (possibly bad API key)"


def test_check_ips(input=[True]):
    from AbuseIPDBPopulateIndicators import check_ips

    assert check_ips(input) is None
