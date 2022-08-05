import json
import os.path

import pytest
import demistomock as demisto


@pytest.fixture()
def advisories_list():
    from CheckPanosVersionAffected import Advisory
    return [
        Advisory(
            data_type='CVE',
            data_format='MITRE',
            cve_id='CVE-2019-17440',
            cve_date_public='2019-12-19T19:35:00.000Z',
            cve_title='PAN-OS on PA-7000 Series: Improper restriction of communication to Log Forwarding Card (LFC)',
            description='Improper restriction of communication',
            cvss_score=10,
            cvss_severity='CRITICAL',
            cvss_vector_string='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            affected_version_list=[
                "PAN-OS 9.0.5",
                "PAN-OS 9.0.4",
                "PAN-OS 9.0.3-h3",
                "PAN-OS 9.0.3-h2",
                "PAN-OS 9.0.3-h1",
                "PAN-OS 9.0.3",
                "PAN-OS 9.0.2-h4",
                "PAN-OS 9.0.2-h3",
                "PAN-OS 9.0.2-h2",
                "PAN-OS 9.0.2-h1",
                "PAN-OS 9.0.2",
                "PAN-OS 9.0.1",
                "PAN-OS 9.0.0",
                "PAN-OS 9.0",
                "PAN-OS 8.1.11"
            ],
        ),
        Advisory(
            data_type='CVE',
            data_format='MITRE',
            cve_id='CVE-2019-17441',
            cve_date_public='2019-12-15T19:35:00.000Z',
            cve_title='This is a fake advisory',
            description='Improper restriction of communication',
            cvss_score=10,
            cvss_severity='CRITICAL',
            cvss_vector_string='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            affected_version_list=[
                "PAN-OS 8.1.12-h3",
                "PAN-OS 8.1.11",
                "PAN-OS 8.1.10"
            ],
        )
    ]


def test_compare_version_with_advisories(advisories_list):
    """
    Given a list of advisories as dataclasses, tests the comparison function
    """
    from CheckPanosVersionAffected import compare_version_with_advisories
    # Match single item
    match = compare_version_with_advisories(panos_version="9.0.5", advisories_list=advisories_list)
    assert len(match) == 1
    assert match[0].cve_id == "CVE-2019-17440"

    # Match multiple advisories
    match = compare_version_with_advisories(panos_version="8.1.11", advisories_list=advisories_list)
    assert len(match) == 2

    # Match no advisories
    match = compare_version_with_advisories(panos_version="7.1.11", advisories_list=advisories_list)
    assert len(match) == 0


def test_main(mocker):
    """
    Tests the complete main() function, including reading advisories in as a list from the context data as it is produced by the
    integration command.
    """
    from CheckPanosVersionAffected import main
    advisories_list = json.load(
        open(os.path.sep.join(["test_data", "example_advisories_data.json"])))

    mocker.patch.object(demisto, 'args', return_value={
        "advisories": advisories_list,
        "version": "9.1.3"
    })
    expected_results = json.load(
        open(os.path.sep.join(["test_data", "expected_response.json"])))
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with(expected_results)
