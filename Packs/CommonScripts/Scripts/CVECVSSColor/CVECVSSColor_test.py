import pytest


@pytest.mark.parametrize('cvss, color', [(10, '#FF4040'), (6, '#FFA07A'), (1, '#50C878'), (0, '#000000')])
def test_cvss_color(cvss, color):
    """
    Given:
        A CVSS score in the correct structure within the context

    When:
        The script is called

    Then:
        return a color in hef format
    """

    from CVECVSSColor import get_color
    assert get_color(cvss) == color
