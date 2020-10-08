from IsInternalDomainName import check_sub_domains_in_domain
import pytest


@pytest.mark.parametrize('domain_name, domain_to_check,  expected_output', [
    # domain valid
    ("paloaltonetworks.com",
     ["paloaltonetworks.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", "paloaltonetworks.com", True),
      ("apps.paloaltonetworks.com", "paloaltonetworks.com", True)]
     ),
    # domain NOT valid
    ("ppaloaltonetworks.com",
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", "ppaloaltonetworks.com", False),
      ("paloaltonetworkss.com", "ppaloaltonetworks.com", False),
      ("apps.paloaltonetworks.com", "ppaloaltonetworks.com", False)]
     ),
    ("paloaltonetworks.com",
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", "paloaltonetworks.com", True),
      ("paloaltonetworkss.com", "paloaltonetworks.com", False),
      ("apps.paloaltonetworks.com", "paloaltonetworks.com", True)]
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
    result = check_sub_domains_in_domain(domain_name, domain_to_check)
    for index, sub_domain in enumerate(result.outputs["IsInternalDomain"]):
        assert sub_domain["DomainToTest"] == expected_output[index][0]
        assert sub_domain["DomainToCompare"] == expected_output[index][1]
        assert sub_domain["IsInternal"] == expected_output[index][2]
