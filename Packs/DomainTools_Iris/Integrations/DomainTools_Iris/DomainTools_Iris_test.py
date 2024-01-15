from CommonServerPython import *
from DomainTools_Iris import format_investigate_output, format_enrich_output, main
from test_data import mock_response, expected


def write_test_data(file_path, string_to_write):
    """
        Use this function to save expected action output for asserting future edge cases.
        example:
        human_readable_output, context = format_enrich_output(mock_response.domaintools_response)
        # requires you to replace "\" with "\\" in file for assertions to pass
        write_test_data('new-test-data.txt', human_readable_output)

        Args:
            file_path: file to save test expected output.
            string_to_write: the results to save.
        """
    with open(file_path, "w") as file:
        file.write(string_to_write)


def test_format_investigate():
    human_readable_output, context = format_investigate_output(mock_response.domaintools_response)

    expected_investigate_domaintools_context = expected.domaintools_investigate_context
    domaintools_context = context.get("domaintools")
    assert domaintools_context.get("Name") == expected_investigate_domaintools_context.get("domaintools", {}).get("Name")


def test_format_enrich():
    human_readable_output, context = format_enrich_output(mock_response.domaintools_response)
    expected_enrich_domaintools_context = expected.domaintools_enrich_context
    domaintools_context = context.get("domaintools")
    assert domaintools_context.get("Name") == expected_enrich_domaintools_context.get("domaintools", {}).get("Name")


def test_analytics_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintoolsiris-analytics")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        'DomainTools_Iris.domain_investigate',
        return_value={
            'results_count': 1,
            'results': [
                mock_response.domaintools_response]})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['domain'] == 'domaintools.com'


def test_threat_profile_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintoolsiris-threat-profile")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        'DomainTools_Iris.domain_investigate',
        return_value={
            'results_count': 1,
            'results': [
                mock_response.domaintools_response]})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['domain'] == 'domaintools.com'


def test_pivot_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintoolsiris-pivot")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "domain": "domaintools.com",
            "ip": "104.16.124.175",
            "include_context": True})
    mocker.patch(
        'DomainTools_Iris.domain_pivot',
        return_value={
            'has_more_results': False,
            'results_count': 1,
            'results': mock_response.pivot_response})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['Value'] == '104.16.124.175'


def test_whois_history_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-whois-history")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        'DomainTools_Iris.whois_history',
        return_value={
            'record_count': 2,
            'history': mock_response.whois_history_response})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['Value'] == 'domaintools.com'


def test_hosting_history_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-hosting-history")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        'DomainTools_Iris.hosting_history',
        return_value={
            'record_count': 2,
            'history': mock_response.hosting_history_response})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['Value'] == 'domaintools.com'


def test_reverse_whois_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-reverse-whois")
    mocker.patch.object(demisto, "args", return_value={"terms": "domaintools"})
    mocker.patch('DomainTools_Iris.reverse_whois', return_value=mock_response.reverse_whois_response)

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['Value'] == 'domaintools'


def test_whois_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-whois")
    mocker.patch.object(demisto, "args", return_value={"query": "domaintools.com"})
    mocker.patch('DomainTools_Iris.parsed_whois', return_value=mock_response.parsed_whois_response)

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]

    assert results[0]['EntryContext']['Domain(val.Name && val.Name == obj.Name)'][0]['Name'] == 'domaintools.com'
