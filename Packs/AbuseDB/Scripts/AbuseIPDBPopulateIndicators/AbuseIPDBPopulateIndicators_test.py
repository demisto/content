import pytest

<<<<<<< HEAD
"""HELPER FUNCTIONS"""
=======
from CommonServerPython import DemistoException
>>>>>>> 34f2d35b74 (updated UT)


def test_get_contents():
    from AbuseIPDBPopulateIndicators import get_contents

    assert get_contents({}) is None


@pytest.mark.parametrize("input", ["Too many requests", None])
def test_check_ips_fail(input):
    from AbuseIPDBPopulateIndicators import check_ips

<<<<<<< HEAD
    with pytest.raises(SystemExit) as e:
        check_ips(input)
    assert str(e.typename) == "SystemExit"
=======
    with pytest.raises(DemistoException) as e:
        check_ips(input)
    assert str(e.value) == "No Indicators were created (possibly bad API key)"
>>>>>>> 34f2d35b74 (updated UT)


def test_check_ips(input=[True]):
    from AbuseIPDBPopulateIndicators import check_ips

    assert check_ips(input) is None
