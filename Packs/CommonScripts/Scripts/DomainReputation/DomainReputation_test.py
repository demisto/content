import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_domain_reputation(mocker):
    """
    Given:
        - Script args: A network domain string.
    When:
        - Running ip_reputation function.
    Then:
        - Validating the outputs as expected.
    """
    from DomainReputation import domain_reputation
    mocker.patch.object(demisto, 'args', return_value={'ip': 'domain.com'})
    execute_command_res = [{'Type': 4, 'Contents': 'Error', 'Brand': 'brand'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    domain_reputation()
    assert execute_mock.call_count == 1
    assert 'returned an error' in results_mock.call_args[0][0][0]['Contents']
    from DomainReputation import domain_reputation


def test_domain_reputation_ignore_offset_error(mocker):
    """
    Given:
        - Script args: A network domain string.
    When:
        - Running domain_reputation function using VT integration and an error entry (type 4) of "offset 1" is returned.
    Then:
        - Ensure the script will ignore the offset 1 error.
    """
    from DomainReputation import domain_reputation
    mocker.patch.object(demisto, 'args', return_value={'ip': 'domain.com'})
    execute_command_res = [{'Type': 4, 'Contents': "'Offset': 1", 'Brand': 'VirusTotal (API v3)'}]
    execute_mock = mocker.patch.object(demisto, 'executeCommand', return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, 'results')
    domain_reputation()
    assert execute_mock.call_count == 1
    assert 'returned an error' not in results_mock.call_args[0][0][0]['Contents']
