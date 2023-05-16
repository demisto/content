import pytest


@pytest.mark.parametrize('cvss, color', [(10, '#FF4040'), (6, '#FFA07A'), (1, '#50C878'), (0, '#000000')])
def test_cvss_color(cvss, color):
    from CVECVSSColor import get_color
    assert get_color(cvss) == color
