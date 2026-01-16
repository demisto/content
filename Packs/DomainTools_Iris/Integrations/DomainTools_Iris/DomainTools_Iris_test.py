import pytest

from CommonServerPython import *
from DomainTools_Iris import (
    format_investigate_output,
    format_enrich_output,
    format_tags,
    format_attribute,
    main,
    http_request,
    API,
    chunks,
    fetch_domains_from_dt_api,
    create_domain_risk_results,
)
from test_data import mock_response, expected


@pytest.fixture
def dt_client():
    return API(username="test", key="test", verify_ssl=False)


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
        "DomainTools_Iris.domain_investigate",
        return_value={
            "results_count": 1,
            "results": [mock_response.domaintools_response],
        },
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["domain"] == "domaintools.com"


def test_threat_profile_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintoolsiris-threat-profile")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        "DomainTools_Iris.domain_investigate",
        return_value={
            "results_count": 1,
            "results": [mock_response.domaintools_response],
        },
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["domain"] == "domaintools.com"


def test_pivot_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintoolsiris-pivot")
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "domain": "domaintools.com",
            "ip": "104.16.124.175",
            "include_context": True,
        },
    )
    mocker.patch(
        "DomainTools_Iris.domain_pivot",
        return_value={
            "has_more_results": False,
            "results_count": 1,
            "results": mock_response.pivot_response,
        },
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["Value"] == "104.16.124.175"


def test_whois_history_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-whois-history")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        "DomainTools_Iris.whois_history",
        return_value={
            "record_count": 2,
            "history": mock_response.whois_history_response,
        },
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["Value"] == "domaintools.com"


def test_hosting_history_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-hosting-history")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})
    mocker.patch(
        "DomainTools_Iris.hosting_history",
        return_value={
            "record_count": 2,
            "history": mock_response.hosting_history_response,
        },
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["Value"] == "domaintools.com"


def test_reverse_whois_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-reverse-whois")
    mocker.patch.object(demisto, "args", return_value={"terms": "domaintools"})
    mocker.patch(
        "DomainTools_Iris.reverse_whois",
        return_value=mock_response.reverse_whois_response,
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert results[0]["Contents"]["Value"] == "domaintools"


def test_whois_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domaintools-whois")
    mocker.patch.object(demisto, "args", return_value={"query": "domaintools.com"})
    mocker.patch(
        "DomainTools_Iris.parsed_whois",
        return_value=mock_response.parsed_whois_response,
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]

    assert results[0]["EntryContext"]["Domain(val.Name && val.Name == obj.Name)"][0]["Name"] == "domaintools.com"


def test_domainRdap_command(mocker):
    mocker.patch.object(demisto, "command", return_value="domainRdap")
    mocker.patch.object(demisto, "args", return_value={"domain": "domaintools.com"})

    mock_resp = {
        "_raw": mock_response.raw_parsed_domain_rdap_response,
        "flat": mock_response.flattened_parsed_domain_rdap_response,
    }

    expected_rdap_response_keys = ["domain_rdap", "parsed_domain_rdap", "record_source"]

    mocker.patch("DomainTools_Iris.parsed_domain_rdap", return_value=mock_resp)

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]

    contents = results[0]["Contents"]
    assert contents["record_source"] == "domaintools.com"
    assert all(True for key in expected_rdap_response_keys if key in contents)

    human_readable = results[0]["HumanReadable"]
    assert human_readable == expected.parsed_domain_rdap_table


def test_testModule_command(mocker):
    mocker.patch.object(demisto, "command", return_value="test-module")

    mocker.patch("DomainTools_Iris.http_request", return_value={})

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert "ok" in results[0]


def test_command_not_implemented(mocker):
    mocker.patch.object(demisto, "command", return_value="unknown-command")
    expected_error_msg = "Unable to perform command : unknown-command, Reason: Command unknown-command is not supported."
    mock_return_error = mocker.patch("DomainTools_Iris.return_error")

    main()

    # Assert that the captured exception message is correct
    mock_return_error.assert_called_once_with(expected_error_msg)


@pytest.mark.parametrize(
    "method, attribute, params",
    [
        ("parsed-domain-rdap", "parsed_domain_rdap", {"domain": "domaintools.com"}),
    ],
)
def test_http_request(mocker, dt_client, method, attribute, params):
    expected_response = {
        "parsed-domain-rdap": mock_response.raw_parsed_domain_rdap_response,
        "parsed-whois": mock_response.parsed_whois_response,
    }

    mocker.patch("DomainTools_Iris.get_client", return_value=dt_client)

    mocker.patch("DomainTools_Iris.USERNAME", return_value="test_username")
    mocker.patch("DomainTools_Iris.API_KEY", return_value="test_key")

    mocker.patch.object(dt_client, attribute, return_value=expected_response[method])

    results = http_request(method, params)

    assert results == expected_response[method]


@pytest.mark.parametrize(
    "args, attribute, type",
    [
        ({"domain": "google.com"}, "reverse_ip", "domain"),
        ({"ip": "8.8.8.8"}, "host_domains", "ip"),
    ],
)
def test_reverseIP_command(mocker, args, attribute, type):
    mocker.patch.object(demisto, "command", return_value="reverseIP")
    mocker.patch.object(demisto, "args", return_value=args)

    mock_api_response = {
        "ip": mock_response.reverseIP_responses.get("ip"),
        "domain": mock_response.reverseIP_responses.get("domain"),
    }

    mocker.patch(f"DomainTools_Iris.{attribute}", return_value=mock_api_response[type])

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]

    contents = results[0]["Contents"]

    assert "ip_addresses" in contents
    if type == "domain":
        assert isinstance(contents["ip_addresses"], list) is True

    human_readable = results[0]["HumanReadable"]

    expected_human_readable = {
        "ip": expected.reverseIP_ip_params_table,
        "domain": expected.reverseIP_domain_params_table,
    }
    assert " ".join(human_readable.split()) == " ".join(expected_human_readable[type].split())


def test_reverseNameserver_command(mocker):
    mocker.patch.object(demisto, "command", return_value="reverseNameServer")
    mocker.patch.object(demisto, "args", return_value={"nameServer": "ns01.domaincontrol.com"})

    mocker.patch(
        "DomainTools_Iris.reverse_nameserver",
        return_value=mock_response.reverseNameserver_response,
    )

    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]

    contents = results[0]["Contents"]

    assert "name_server" in contents
    assert "primary_domains" in contents

    primary_domains = contents.get("primary_domains")
    assert len(primary_domains) == 5

    human_readable = results[0]["HumanReadable"]
    assert " ".join(human_readable.split()) == " ".join(expected.reverseNameserver_table.split())


def test_create_domain_risk_results(mocker):
    domain_risk_results = create_domain_risk_results(mock_response.domaintools_response)
    domaintools_risk = domain_risk_results.get("domaintools")

    assert "Analytics" in domaintools_risk
    assert domaintools_risk["Name"] == "domaintools.com"
    assert domaintools_risk["LastEnriched"] == datetime.now().strftime("%Y-%m-%d")


def test_format_tags(mocker):
    sample_tags = [
        {"label": "tag1"},
        {"label": "tag2"},
    ]

    assert format_tags(sample_tags) == "tag1 tag2"


def test_format_attribute(mocker):
    expected_output = "141.193.213.20,141.193.213.21"
    test_attr = mock_response.domaintools_response.get("ip")
    formatted_value = format_attribute(test_attr, key="address.value")

    assert expected_output == formatted_value


def test_chunks(mocker):
    sample_list_results = [{"result": "test"}] * 10000
    test_chunks = chunks(sample_list_results, 100)

    # test the len if chunks are working as expected
    test_chunk_result = next(test_chunks)

    assert len(test_chunk_result) == 100


def test_fetch_domains_from_dt_api(mocker):
    # mocker.patch(f"DomainTools_Iris.fetch_domains_from_dt_api", return_value=[])
    mocker.patch(
        "DomainTools_Iris.domain_pivot", return_value={"results": [mock_response.domaintools_response], "has_more_results": False}
    )

    test_fetch_result = fetch_domains_from_dt_api("domain", "domaintools.com")

    assert len(test_fetch_result) == 1
