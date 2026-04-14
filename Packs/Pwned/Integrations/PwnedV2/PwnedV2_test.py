import json
import os
import sys
from unittest.mock import MagicMock

import demistomock as demisto
import PwnedV2
import pytest
from PwnedV2 import (
    error_handler,
    pwned_domain_command,
    pwned_email_command,
    pwned_username_command,
    pwned_breaches_for_domain_list_command,
    pwned_subscribed_domains_list_command,
    pwned_latest_breach_get_command,
    pwned_breach_get_command,
)

RETURN_ERROR_TARGET = "PwnedV2.return_error"

username_context = {
    "Domain(val.Name && val.Name == obj.Name)": {
        "Name": "jondon",
        "Pwned-V2": {"Compromised": {"Vendor": "Have I Been Pwned? V2", "Reporters": "Gawker, hackforums.net"}},
        "Malicious": {"Vendor": "Have I Been Pwned? V2", "Description": "The domain has been compromised"},
    },
    "DBotScore": {
        "Indicator": "jondon",
        "Type": "domain",
        "Vendor": "Have I Been Pwned? V2",
        "Score": 3,
        "Reliability": "A - Completely reliable",
    },
}

domain_context = {
    "Domain(val.Name && val.Name == obj.Name)": {
        "Name": "adobe.com",
        "Pwned-V2": {"Compromised": {"Vendor": "Have I Been Pwned? V2", "Reporters": "Adobe"}},
        "Malicious": {"Vendor": "Have I Been Pwned? V2", "Description": "The domain has been compromised"},
    },
    "DBotScore": {
        "Indicator": "adobe.com",
        "Type": "domain",
        "Vendor": "Have I Been Pwned? V2",
        "Score": 3,
        "Reliability": "A - Completely reliable",
    },
}

username_req = [
    {
        "PwnCount": 1247574,
        "Domain": "gawker.com",
        "IsSensitive": False,
        "Name": "Gawker",
        "Title": "Gawker",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"],
        "IsRetired": False,
        "IsSpamList": False,
        "BreachDate": "2010-12-11",
        "IsFabricated": False,
        "ModifiedDate": "2013-12-04T00:00:00Z",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Gawker.png",
        "AddedDate": "2013-12-04T00:00:00Z",
        "IsVerified": True,
        "Description": "In December 2010, Gawker was attacked by the hacker collective &quot;Gnosis&quot;"
        " in retaliation for what was"
        " reported to be a feud between Gawker and 4Chan. Information about Gawkers 1.3M users was published along"
        " with the data from Gawker's other web presences including Gizmodo and Lifehacker. Due to the prevalence of"
        ' password reuse, many victims of the breach <a href="http://www.troyhunt.com/2011/01/why-your-apps-security'
        '-design-could.html" target="_blank" rel="noopener">then had their Twitter accounts compromised to send Acai'
        " berry spam</a>.",
    },
    {
        "PwnCount": 191540,
        "Domain": "hackforums.net",
        "IsSensitive": False,
        "Name": "HackForums",
        "Title": "hackforums.net",
        "DataClasses": [
            "Dates of birth",
            "Email addresses",
            "Instant messenger identities",
            "IP addresses",
            "Passwords",
            "Social connections",
            "Spoken languages",
            "Time zones",
            "User website URLs",
            "Usernames",
            "Website activity",
        ],
        "IsRetired": False,
        "IsSpamList": False,
        "BreachDate": "2011-06-25",
        "IsFabricated": False,
        "ModifiedDate": "2014-05-11T10:30:43Z",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/HackForums.png",
        "AddedDate": "2014-05-11T10:30:43Z",
        "IsVerified": True,
        "Description": 'In June 2011, the hacktivist group known as "LulzSec" leaked <a href='
        '"http://www.forbes.com/sites/andygreenberg/2011/06/25/lulzsec-says-goodbye-'
        'dumping-nato-att-gamer-data/" target="_blank" rel="noopener">one final large'
        ' data breach they titled "50 days of lulz"</a>. The compromised data came from'
        ' sources such as AT&T, Battlefield Heroes and the <a href="http://hackforums.'
        'net" target="_blank" rel="noopener">hackforums.net website</a>. The leaked '
        "Hack Forums data included credentials and personal "
        "information of nearly 200,000 registered forum users.",
    },
]

domain_req = [
    {
        "PwnCount": 152445165,
        "Domain": "adobe.com",
        "IsSensitive": False,
        "Name": "Adobe",
        "Title": "Adobe",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsRetired": False,
        "IsSpamList": False,
        "BreachDate": "2013-10-04",
        "IsFabricated": False,
        "ModifiedDate": "2013-12-04T00:00:00Z",
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
        "AddedDate": "2013-12-04T00:00:00Z",
        "IsVerified": True,
        "Description": "In October 2013, 153 million Adobe accounts were breached with each"
        " containing an internal ID, username, email, <em>encrypted</em> password and"
        " a password hint in plain text. The password cryptography was poorly done"
        ' and <a href="http://stricture-group.com/files/adobe-top100.txt" target="_'
        'blank" rel="noopener">many were quickly resolved back to plain text</a>. '
        'The unencrypted hints also <a href="http://www.troyhunt.com/2013/11/adobe-'
        'credentials-and-serious.html" target="_blank" rel="noopener">disclosed much'
        " about the passwords</a> adding further to the risk that hundreds of "
        "millions of Adobe customers already faced.",
    }
]

args1 = {"username": "jondon", "domain": "adobe.com"}


@pytest.mark.parametrize(
    "command, args, response, expected_result",
    [(pwned_username_command, args1, username_req, username_context), (pwned_domain_command, args1, domain_req, domain_context)],
)
def test_pwned_commands(command, args, response, expected_result, mocker):
    """Unit test
    Given
    - command args - e.g username, mail
    - response of the database
    When
    - mock the website result
    Then
    - convert the result to human readable table
    - create the context
    validate the expected_result and the created context
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mocker.patch("PwnedV2.http_request", return_value=response)
    md_list, ec_list, api_email_res_list = command(args)
    for _hr, outputs, _raw in zip(md_list, ec_list, api_email_res_list):
        assert expected_result == outputs  # entry context is found in the 2nd place in the result of the command


def test_valid_emails(mocker):
    """
    Given:
    - A list of valid email addresses.

    When:
    - Calling the pwned_email_command function.

    Then:
    - Ensure the function returns the expected output.
    """
    email_list = ["test1@example.com", "test2@example.com"]
    api_email_res_list = [
        {
            "Title": "Breach1",
            "Domain": "example.com",
            "PwnCount": 100,
            "IsVerified": True,
            "BreachDate": "2021-01-01T00:00:00Z",
            "Description": "<p>Breach description</p>",
            "DataClasses": ["Emails", "Passwords"],
        },
        None,
    ]
    api_paste_res_list = [
        [{"Source": "Paste1", "Title": "Paste Title", "Id": "1234", "Date": "2021-01-01T00:00:00Z", "EmailCount": 10}],
        [],
    ]
    expected_md_list = [
        "### Have I Been Pwned query for email: *test1@example.com*\n"
        "#### Breach1 (example.com): 100 records breached [Verified breach]\n"
        "Date: **2021-01-01**\n\n"
        "Breach description\n"
        "Data breached: **Emails,Passwords**\n"
        "\n"
        'The email address was found in the following "Pastes":\n'
        "| ID | Title | Date | Source | Amount of emails in paste |\n"
        "|----|-------|------|--------|--------------------------|\n"
        "| 1234 | Paste Title | 2021-01-01 | Paste1 | 10 |\n",
        "### Have I Been Pwned query for email: *test2@example.com*\nNo records found",
    ]
    expected_ec_list = [
        {
            "DBotScore": {
                "Indicator": "test1@example.com",
                "Type": "email",
                "Vendor": "HaveIBeenPwned",
                "Score": 3,
                "Reliability": "B - Usually reliable",
            },
            "email": {
                "Address": "test1@example.com",
                "Pwned-V2": {"Compromised": {"Vendor": "HaveIBeenPwned", "Reporters": "Breach1, Paste1"}},
                "Malicious": {"Vendor": "HaveIBeenPwned", "Description": "The email has been compromised"},
            },
        },
        {
            "DBotScore": {
                "Indicator": "test2@example.com",
                "Type": "email",
                "Vendor": "HaveIBeenPwned",
                "Score": 0,
                "Reliability": "B - Usually reliable",
            },
            "email": {"Address": "test2@example.com", "Pwned-V2": {"Compromised": {"Vendor": "HaveIBeenPwned", "Reporters": ""}}},
        },
    ]

    mocker.patch.object(demisto, "params", return_value={"integrationReliability": "B - Usually reliable"})
    mocker.patch.object(demisto, "command", return_value="pwned-email")
    mocker.patch.object(demisto, "args", return_value={"email": email_list})
    mocker.patch("PwnedV2.pwned_email", return_value=(api_email_res_list, api_paste_res_list))
    mocker.patch("PwnedV2.data_to_markdown", side_effect=expected_md_list)
    mocker.patch("PwnedV2.email_to_entry_context", side_effect=expected_ec_list)

    md_list, ec_list, api_paste_res = pwned_email_command(demisto.args())

    assert md_list == expected_md_list
    assert ec_list == expected_ec_list


def test_error_handler_404():
    # Mock response object with 404 status code
    res = MagicMock()
    res.status_code = 404

    with pytest.raises(Exception) as excinfo:
        error_handler(res)

    assert str(excinfo.value) == "No result found."


def test_error_handler_other_status_code(mocker):
    # Mock response object with non-404 status code
    res = MagicMock()
    res.status_code = 500
    res.text = "Internal Server Error"

    mocker.patch.object(sys, "exit")
    mocker.patch.object(demisto, "error")
    mocker.spy(demisto, "results")

    expected_message = "Error in API call to Pwned Integration"

    error_handler(res)

    assert expected_message in demisto.results.call_args.args[0].get("Contents")


def load_test_data(filename: str) -> dict | list:
    """Load a JSON test data file from the test_data directory."""
    test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")
    with open(os.path.join(test_data_dir, filename)) as f:
        return json.load(f)


def test_pwned_breaches_for_domain_list_command_no_results(mocker):
    """Unit test
    Given
    - A domain to check for breaches
    When
    - The API returns no results (404 / None) for the domain
    Then
    - Verify the command returns the expected "no email addresses" markdown and empty context
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mocker.patch("PwnedV2.http_request", return_value=None)

    md_list, ec_list, api_res_list = pwned_breaches_for_domain_list_command({"domain": "example.com"})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    assert "The domain does not have any email addresses" in md_list[0]
    assert ec_list[0] == {}
    assert api_res_list[0] is None


def test_pwned_breaches_for_domain_list_command_with_results(mocker):
    """Unit test
    Given
    - A domain to check for breaches
    When
    - The API returns breached email addresses for the domain
    Then
    - Verify the command returns a markdown table with Domain, Account, and Breaches columns
    - Verify the entry context contains the breached domain data under Domain.Pwned-V2.Breaches
    - Verify the raw response matches the API response
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mock_response = load_test_data("breached_domain_response.json")
    mocker.patch("PwnedV2.http_request", return_value=mock_response)

    md_list, ec_list, api_res_list = pwned_breaches_for_domain_list_command({"domain": "example.com"})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    # Verify the raw API response is returned
    assert api_res_list[0] == mock_response
    # Verify the markdown contains breach information
    assert "Breaches for domain" in md_list[0]
    assert "alias1" in md_list[0]
    assert "Adobe" in md_list[0]
    # Verify the entry context contains the breached domain data
    assert ec_list[0] == {"Domain.Pwned-V2.Breaches": mock_response}


def test_pwned_subscribed_domains_list_command_no_results(mocker):
    """Unit test
    Given
    - A request to list subscribed domains
    When
    - The API returns no results (None)
    Then
    - Verify the command returns the expected "no subscribed domains" message
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mocker.patch("PwnedV2.http_request", return_value=None)

    md_list, ec_list, api_res_list = pwned_subscribed_domains_list_command({})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    assert "No subscribed domains found." in md_list[0]
    assert ec_list[0] == {}
    assert api_res_list[0] is None


def test_pwned_subscribed_domains_list_command_with_results(mocker):
    """Unit test
    Given
    - A request to list subscribed domains
    When
    - The API returns a list of subscribed domain objects
    Then
    - Verify the command returns a markdown table with domain information
    - Verify the entry context contains the subscribed domain data under Pwned-V2.SubscribedDomain
    - Verify the raw response matches the API response
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mock_response = load_test_data("subscribed_domains_response.json")
    mocker.patch("PwnedV2.http_request", return_value=mock_response)

    md_list, ec_list, api_res_list = pwned_subscribed_domains_list_command({})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    # Verify the raw API response is returned
    assert api_res_list[0] == mock_response
    # Verify the markdown contains domain information
    assert "Subscribed Domains" in md_list[0]
    assert "example.com" in md_list[0]
    assert "test.org" in md_list[0]
    # Verify the entry context contains the subscribed domain data
    assert ec_list[0] == {"Pwned-V2.SubscribedDomain": mock_response}


def test_pwned_latest_breach_get_command_no_results(mocker):
    """Unit test
    Given
    - A request to get the latest breach
    When
    - The API returns no results (None)
    Then
    - Verify the command returns the expected "no latest breach" message
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mocker.patch("PwnedV2.http_request", return_value=None)

    md_list, ec_list, api_res_list = pwned_latest_breach_get_command({})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    assert "No latest breach found." in md_list[0]
    assert ec_list[0] == {}
    assert api_res_list[0] is None


def test_pwned_latest_breach_get_command_with_results(mocker):
    """Unit test
    Given
    - A request to get the latest breach
    When
    - The API returns a breach object
    Then
    - Verify the command returns a markdown table with breach details
    - Verify the entry context is built using domain_to_entry_context
    - Verify the raw response matches the API response
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mock_response = load_test_data("latest_breach_response.json")
    mocker.patch("PwnedV2.http_request", return_value=mock_response)

    md_list, ec_list, api_res_list = pwned_latest_breach_get_command({})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    # Verify the raw API response is returned
    assert api_res_list[0] == mock_response
    # Verify the markdown contains breach details
    assert "Latest Breach" in md_list[0]
    assert "latestbreach.com" in md_list[0]
    # Verify the entry context is built with domain_to_entry_context
    expected_ec = {
        "Domain(val.Name && val.Name == obj.Name)": {
            "Name": "latestbreach.com",
            "Pwned-V2": {
                "Compromised": {"Vendor": "Have I Been Pwned? V2", "Reporters": "Latest Breach"},
                "Name": "LatestBreach",
                "Title": "Latest Breach",
                "Domain": "latestbreach.com",
                "BreachDate": "2024-12-01",
                "AddedDate": "2025-01-15T00:00:00Z",
                "ModifiedDate": "2025-01-15T00:00:00Z",
                "PwnCount": 50000,
                "Description": "A recent breach affecting 50,000 accounts.",
                "LogoPath": "https://logos.haveibeenpwned.com/LatestBreach.png",
                "Attribution": None,
                "DisclosureUrl": None,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsFabricated": False,
                "IsSensitive": False,
                "IsRetired": False,
                "IsSpamList": False,
                "IsMalware": False,
                "IsSubscriptionFree": False,
                "IsStealerLog": False,
            },
            "Malicious": {"Vendor": "Have I Been Pwned? V2", "Description": "The domain has been compromised"},
        },
        "DBotScore": {
            "Indicator": "latestbreach.com",
            "Type": "domain",
            "Vendor": "Have I Been Pwned? V2",
            "Score": 3,
            "Reliability": "A - Completely reliable",
        },
    }
    assert ec_list[0] == expected_ec


def test_pwned_breach_get_command_no_results(mocker):
    """Unit test
    Given
    - A breach name to look up
    When
    - The API returns no results (404 / None)
    Then
    - Verify the command returns the expected "no breach found" message
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mocker.patch("PwnedV2.http_request", return_value=None)

    md_list, ec_list, api_res_list = pwned_breach_get_command({"breach_name": "NonExistent"})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    assert "No breach found for name: NonExistent" in md_list[0]
    assert ec_list[0] == {}
    assert api_res_list[0] is None


def test_pwned_breach_get_command_with_results(mocker):
    """Unit test
    Given
    - A breach name to look up
    When
    - The API returns a breach object for the given name
    Then
    - Verify the command returns a markdown table with breach details
    - Verify the entry context is built using domain_to_entry_context
    - Verify the raw response matches the API response
    """
    PwnedV2.API_KEY = "test"
    mocker.patch.object(
        demisto,
        "params",
        return_value={"integrationReliability": "A - Completely reliable", "credentials_api_key": {"password": "test"}},
    )
    mock_response = load_test_data("single_breach_response.json")
    mocker.patch("PwnedV2.http_request", return_value=mock_response)

    md_list, ec_list, api_res_list = pwned_breach_get_command({"breach_name": "Adobe"})

    assert len(md_list) == 1
    assert len(ec_list) == 1
    assert len(api_res_list) == 1
    # Verify the raw API response is returned
    assert api_res_list[0] == mock_response
    # Verify the markdown contains breach details
    assert "Adobe" in md_list[0]
    assert "adobe.com" in md_list[0]
    # Verify the entry context is built with domain_to_entry_context
    expected_ec = {
        "Domain(val.Name && val.Name == obj.Name)": {
            "Name": "adobe.com",
            "Pwned-V2": {
                "Compromised": {"Vendor": "Have I Been Pwned? V2", "Reporters": "Adobe"},
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "AddedDate": "2013-12-04T00:00:00Z",
                "ModifiedDate": "2022-05-15T23:52:49Z",
                "PwnCount": 152445165,
                "Description": "In October 2013, 153 million Adobe accounts were breached.",
                "LogoPath": "https://logos.haveibeenpwned.com/Adobe.png",
                "Attribution": None,
                "DisclosureUrl": None,
                "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                "IsVerified": True,
                "IsFabricated": False,
                "IsSensitive": False,
                "IsRetired": False,
                "IsSpamList": False,
                "IsMalware": False,
                "IsSubscriptionFree": False,
                "IsStealerLog": False,
            },
            "Malicious": {"Vendor": "Have I Been Pwned? V2", "Description": "The domain has been compromised"},
        },
        "DBotScore": {
            "Indicator": "adobe.com",
            "Type": "domain",
            "Vendor": "Have I Been Pwned? V2",
            "Score": 3,
            "Reliability": "A - Completely reliable",
        },
    }
    assert ec_list[0] == expected_ec
