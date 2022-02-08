import pytest

from CommonServerPython import BaseClient, DemistoException
from FireEyeApiModule import to_fe_datetime_converter, alert_severity_to_dbot_score, FireEyeClient



def test_to_fe_datetime_converter():
    """Unit test
    Given
    - to_fe_datetime_converter command
    - time in a string
    When
    - running to_fe_datetime_converter
    Then
    - Validate that the FE time is as expected
    """
    # fe time will not change
    assert to_fe_datetime_converter('2021-05-14T01:08:04.000-02:00') == '2021-05-14T01:08:04.000-02:00'

    # "now"/ "1 day" / "3 months:" time will be without any timezone
    assert to_fe_datetime_converter('now')[23:] == '+00:00'
    assert to_fe_datetime_converter('3 months')[23:] == '+00:00'

    # now > 1 day
    assert to_fe_datetime_converter('now') > to_fe_datetime_converter('1 day')


@pytest.mark.parametrize('severity_str, dbot_score', [
    ('minr', 1),
    ('majr', 2),
    ('crit', 3),
    ('kookoo', 0)
])
def test_alert_severity_to_dbot_score(severity_str, dbot_score):
    """Unit test
    Given
    - alert_severity_to_dbot_score command
    - severity string
    When
    - running alert_severity_to_dbot_score
    Then
    - Validate that the dbot score is as expected
    """
    assert alert_severity_to_dbot_score(severity_str) == dbot_score


def test_exception_in__generate_token(mocker):

    err = "Some error"
    mocker.patch.object(BaseClient, '_http_request', side_effect=DemistoException(err))
    with pytest.raises(DemistoException, match=f'Token request failed. message: {err}'):
        FireEyeClient(base_url='https://test.com', username='test_user', password='password', verify=False,
                           proxy=False)
