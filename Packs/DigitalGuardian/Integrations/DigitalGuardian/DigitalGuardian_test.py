import pytest
import requests_mock

from CommonServerPython import *

RETURN_ERROR_TARGET = 'DigitalGuardian.return_error'

auth_url = "https://authorization_url.com"
arc_url = "https://arc_url.com"


@pytest.fixture(scope='function', autouse=True)
def setup_params(mocker):
    demisto_params = {
        "auth_url": auth_url,
        "arc_url": arc_url,
        "client_id": "client_id",
        "client_secret": "client_secret"
    }
    mocker.patch.object(demisto, 'params', return_value=demisto_params)


def test_test_module(mocker, capfd):
    from DigitalGuardian import main
    with requests_mock.Mocker() as request_mocker:
        mocker.patch.object(demisto, 'command', return_value='test-module')

        request_mocker.register_uri("POST", re.compile(auth_url), json={'access_token': 'access_token'},
                                    status_code=200)
        request_mocker.register_uri("GET", re.compile(arc_url), status_code=200)

        with capfd.disabled():  # ignore stdout
            main()


@pytest.mark.parametrize('dg_severity, demisto_severity',
                         [('Low', 1), ('Medium', 2), ('High', 3), ('Critical', 4), (None, 1), ('Other', 1)])
def test_convert_to_demisto_severity(dg_severity, demisto_severity):
    from DigitalGuardian import convert_to_demisto_severity

    assert convert_to_demisto_severity(dg_severity) == demisto_severity


@pytest.mark.parametrize('was_classified, demisto_class', [('Yes', 1), ('No', 0), ('other', 0), (None, 0)])
def test_convert_to_demisto_class(was_classified, demisto_class):
    from DigitalGuardian import convert_to_demisto_class

    assert convert_to_demisto_class(was_classified) == demisto_class


@pytest.mark.parametrize('was_classified, demisto_sensitivity',
                         [('Something', "none"), (None, "none"), ('LOW', 'Low'), ("Low", "none"),
                          ('SomethingLOW', 'Low'), ('HIGH', 'High'), ('SomethingHIGH', 'High'), ('MED', 'Medium'),
                          ('SomethingMED', 'Medium'), ('MEDIUM', 'none'), ('', 'none'), ('A', 'none')])
def test_convert_to_demisto_sensitivity(was_classified, demisto_sensitivity):
    from DigitalGuardian import convert_to_demisto_sensitivity

    assert convert_to_demisto_sensitivity(was_classified) == demisto_sensitivity
