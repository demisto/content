from IsInternalDomainName import check_in_domain, get_domains_from_context
import pytest
import demistomock as demisto


@pytest.mark.parametrize('domain_name, domain_to_check,  expected_output', [
    # domain valid
    ("paloaltonetworks.com",
     ["paloaltonetworks.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", True), ("apps.paloaltonetworks.com", True)]
     ),
    # domain NOT valid
    ("ppaloaltonetworks.com",
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", False), ("paloaltonetworkss.com", False), ("apps.paloaltonetworks.com", False)]
     ),
    ("paloaltonetworks.com",
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", True), ("paloaltonetworkss.com", False), ("apps.paloaltonetworks.com", True)]
     ),
])
def test_check_in_domain(domain_name, domain_to_check, expected_output):
    """
    Given:
        - domain name and a list of domains to check

    When:
        - running the script

    Then:
        - returns for each sub domain if it is a sub domain of given domainName or not

    """
    result = check_in_domain(domain_name, domain_to_check)
    for i, element in enumerate(result.outputs):
        assert element["Domain.Name"] == expected_output[i][0]
        assert element["Domain.IsInternal"] == expected_output[i][1]


@pytest.mark.parametrize('context_path, context,  expected_output', [
    # domain valid
    ("Domain.Name",
     {"Domain": "Name",
      "Name": ["paloaltonetworks.com", "google.com", "app.paloaltonetworks.com"]},
     ["paloaltonetworks.com", "google.com", "app.paloaltonetworks.com"]
     ),
    # context path NOT valid
    ("Domain.Name.No",
     {"Domain": "Name", "Name": ["paloaltonetworks.com", "google.com", "app.paloaltonetworks.com"]},
     list()
     ),
    (
        # no domains in the list
        "Domain.Name",
        {"Domain": "Name", "Name": []},
        list()
    )
])
def test_get_domains_from_context(mocker, context_path, context, expected_output):
    """
    Given:
        - context path to look for list of domains

    When:
        - running the script

    Then:
        - returns list of domains' names
    """
    mocker.patch.object(demisto, "context", return_value=context)
    assert get_domains_from_context(context_path) == expected_output
