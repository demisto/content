from IsInternalDomainName import check_sub_domains_in_domain, is_sub_domain_contained
import pytest


@pytest.mark.parametrize('domain_name, domain_to_check,  expected_output', [
    # domain valid
    (["paloaltonetworks.com", "paloaltonetworkss.coms"],
     ["paloaltonetworks.com", "apps.paloaltonetworks.com", "a.paloaltonetworkss.coms"],
     [("paloaltonetworks.com", ["paloaltonetworks.com", "paloaltonetworkss.coms"], True),
      ("apps.paloaltonetworks.com", ["paloaltonetworks.com", "paloaltonetworkss.coms"], True),
      ("a.paloaltonetworkss.coms", ["paloaltonetworks.com", "paloaltonetworkss.coms"], True)]
     ),
    # domain NOT valid
    (["ppaloaltonetworks.com", "bla.com"],
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", ["ppaloaltonetworks.com", "bla.com"], False),
      ("paloaltonetworkss.com", ["ppaloaltonetworks.com", "bla.com"], False),
      ("apps.paloaltonetworks.com", ["ppaloaltonetworks.com", "bla.com"], False)]
     ),
    (["paloaltonetworks.com"],
     ["paloaltonetworks.com", "paloaltonetworkss.com", "apps.paloaltonetworks.com"],
     [("paloaltonetworks.com", ["paloaltonetworks.com"], True),
      ("paloaltonetworkss.com", ["paloaltonetworks.com"], False),
      ("apps.paloaltonetworks.com", ["paloaltonetworks.com"], True)]
     ),
    (["cig.eu"], ["abcdcig.eu"], [("abcdcig.eu", ["cig.eu"], False)]),
    (["cd.com"], ["ab-cd.com"], [("ab-cd.com", ["cd.com"], False)]),
    (["ab-cd.com"], ["zz.ab-cd.com"], [("zz.ab-cd.com", ["ab-cd.com"], True)]),

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


@pytest.mark.parametrize('main_domain, sub_domain, expected_output',
                         [("paloaltonetworks.com", "apps.paloaltonetworks.com", True),
                          ("cd.com", "ab-cd.com", False),
                          ("cig.eu", "abcdcig.eu", False)])
def test_extract_main_domain(main_domain, sub_domain, expected_output):
    """
    Given:
        - A main domain and a sub domain
    When:
        - Checking if the main_domain contains the sub_domain
    Then:
        - Return True if the main_domain contains the sub_domain, False otherwise
    """
    assert is_sub_domain_contained(main_domain, sub_domain) == expected_output
