import pytest

TEST_DATA_URL = {
    "url": [
        "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN",
        "http://microsoft365cpmsetup.com",  # pylint: disable=W9013
        "http://portal-digitalshadows.com.still.valid/learn/risk-profiles/MARKED_DOCUMENT",  # pylint: disable=W9013
        "https://http://microsoft365cpmsetup.com/triage/alerts/BGWZC",
        "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb-e0fd72944a11",
        "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb-e0fd72944a11",
    ]
}

TEST_DATA_URL_EXPECTED = [
    "http://microsoft365cpmsetup.com OR https://http://microsoft365cpmsetup.com/triage/alerts/BGWZC OR "  # pylint: disable=W9013
    + "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN OR "
    + "http://portal-digitalshadows.com.still.valid/learn/risk-profiles/MARKED_DOCUMENT",  # pylint: disable=W9013
    "https://http://microsoft365cpmsetup.com/api/external/resources/2de38dac-bba5-46c9-9ceb-e0fd72944a11",
]

TEST_DATA_URL_SINGLE = {
    "url": "https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN"
}
TEST_DATA_URL_SINGLE_EXPECTED = (
    ["https://http://GermDetectives.com/learn/risk-profiles/IMPERSONATING_DOMAIN"]
)
TEST_DATA_URL_SINGLE_FILTER = {
    "url": "https://portal-digitalshadows.com/learn/risk-profiles/MARKED_DOCUMENT"
}

TEST_DATA_IP = {
    "ip": [
        "192.168.0.1",
        "0.0.0.0",
        "1.1.1.1",
        "123.456.2.124"
    ]
}
TEST_DATA_IP_EXPECTED = ["192.168.0.1 OR 1.1.1.1 OR 123.456.2.124"]

TEST_DATA_IP_SINGLE = {
    "ip": "192.168.0.1"
}
TEST_DATA_IP_SINGLE_EXPECTED = ["192.168.0.1"]

TEST_DATA_IP_SINGLE_FILTER = {
    "ip": "0.0.0.0"
}

TEST_DATA_DOMAIN = {
    "domain": [
        "GermDetectives.com",
        "TutorialFriend.com",
        "LessIsFull.com",
        "SaveJam.com",
        "SaveItDay.com",
        "portal-digitalshadows.com.still.valid",
        "portal-digitalshadows.com"
    ]
}
TEST_DATA_DOMAIN_EXPECTED = [
    "GermDetectives.com OR TutorialFriend.com OR LessIsFull.com OR SaveJam.com OR SaveItDay.com OR "
    + "portal-digitalshadows.com.still.valid"
]

TEST_DATA_DOMAIN_SINGLE = {
    "domain": "GermDetectives.com"
}
TEST_DATA_DOMAIN_SINGLE_EXPECTED = ["GermDetectives.com"]
TEST_DATA_DOMAIN_FILTER = {
    "domain": "portal-digitalshadows.com"
}

TEST_DATA_FILE_SHA1 = {
    "sha1": [
        "fd340743293eae593da4796e868ce57dfabf4147",
        "fd340743293eae593da4796e868ce57dfabf4147",
        "4eeff478822995573f4a5c45e746f01f93e23f28"
    ]
}
TEST_DATA_FILE_SHA1_EXPECTED = [
    "fd340743293eae593da4796e868ce57dfabf4147 OR fd340743293eae593da4796e868ce57dfabf4147 OR "
    + "4eeff478822995573f4a5c45e746f01f93e23f28"
]

TEST_DATA_FILE_SHA1_SINGLE = {
    "sha1": "fd340743293eae593da4796e868ce57dfabf4147"
}
TEST_DATA_FILE_SHA1_SINGLE_EXPECTED = ["fd340743293eae593da4796e868ce57dfabf4147"]

TEST_DATA_FILE_SHA256 = {
    "sha256": [
        "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d",
        "8dca20e35098837cc003b54f17688386aabd9a5640884f5e4397e755ca8bc606"
    ],
    "md5": "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
}
TEST_DATA_FILE_SHA256_EXPECTED = [
    "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d OR "
    + "8dca20e35098837cc003b54f17688386aabd9a5640884f5e4397e755ca8bc606"
]

TEST_DATA_FILE_SHA256_SINGLE = {
    "sha256": "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
}
TEST_DATA_FILE_SHA256_SINGLE_EXPECTED = [
    "57b0ed216fac388b6d99774d256fa5542d32cfdfe72a45b32fd7932ec154731d"
]

TEST_DATA_FILE_MD5 = {
    "sha1": "fd8df0f90ab838325b4e442322b7343e",
    "md5": [
        "fd8df0f90ab838325b4e442322b7343e",
        "5f09950f7c75828ed0ea296853b518c1"
    ]
}
TEST_DATA_FILE_MD5_EXPECTED = [
    "fd8df0f90ab838325b4e442322b7343e OR 5f09950f7c75828ed0ea296853b518c1"
]

TEST_DATA_FILE_MD5_SINGLE = {
    "md5": "fd8df0f90ab838325b4e442322b7343e"
}
TEST_DATA_FILE_MD5_SINGLE_EXPECTED = ["fd8df0f90ab838325b4e442322b7343e"]

TEST_DATA_CVE = {
    "cve": [
        "CVE-2012-2311",
        "CVE-2012-1823",
        "CVE-2022-34491"
    ]
}
TEST_DATA_CVE_EXPECTED = ["CVE-2012-2311 OR CVE-2012-1823 OR CVE-2022-34491"]

TEST_DATA_CVE_SINGLE = {"cve": "CVE-2012-2311"}
TEST_DATA_CVE_SINGLE_EXPECTED = ["CVE-2012-2311"]


@pytest.mark.parametrize(
    "query, output",
    [
        ("alarmautomatika.com", 2),
        ('"alarmautomatika.com"', 1),
        ('"Term 1"', 1),
        ('Term1 AND "Term 2" OR (Term3 Term4)', 4),
        ('frumvarpið "stæðist ekki" AND stjórnarskrá', 3),
        ("$ £", 0),
        ("  ", 0),
        ("AND", 1),
    ],
)
def test_countTerms(query, output):
    from DsSearchQueryArray import count_terms
    assert count_terms(query) == output


@pytest.mark.parametrize(
    "query, expected",
    [
        (TEST_DATA_URL, TEST_DATA_URL_EXPECTED),
        (TEST_DATA_URL_SINGLE, TEST_DATA_URL_SINGLE_EXPECTED),
        (TEST_DATA_URL_SINGLE_FILTER, []),
        (TEST_DATA_IP_SINGLE, TEST_DATA_IP_SINGLE_EXPECTED),
        (TEST_DATA_IP_SINGLE_FILTER, []),
        (TEST_DATA_DOMAIN_SINGLE, TEST_DATA_DOMAIN_SINGLE_EXPECTED),
        (TEST_DATA_DOMAIN_FILTER, []),
        (TEST_DATA_FILE_SHA1_SINGLE, TEST_DATA_FILE_SHA1_SINGLE_EXPECTED),
        (TEST_DATA_FILE_MD5_SINGLE, TEST_DATA_FILE_MD5_SINGLE_EXPECTED),
        (TEST_DATA_FILE_SHA256_SINGLE, TEST_DATA_FILE_SHA256_SINGLE_EXPECTED),
        (TEST_DATA_CVE_SINGLE, TEST_DATA_CVE_SINGLE_EXPECTED),
        (TEST_DATA_IP, TEST_DATA_IP_EXPECTED),
        (TEST_DATA_DOMAIN, TEST_DATA_DOMAIN_EXPECTED),
        (TEST_DATA_FILE_SHA1, TEST_DATA_FILE_SHA1_EXPECTED),
        (TEST_DATA_FILE_SHA256, TEST_DATA_FILE_SHA256_EXPECTED),
        (TEST_DATA_FILE_MD5, TEST_DATA_FILE_MD5_EXPECTED),
        (TEST_DATA_CVE, TEST_DATA_CVE_EXPECTED),
    ],
)
def test_createSingleString(query, expected):
    from DsSearchQueryArray import convert_to_ds_query_array

    result = convert_to_ds_query_array(query)
    for r, e in zip(result, expected):
        r_split = sorted(r.split(' OR '))
        e_split = sorted(e.split(' OR '))
        for r_term, e_term in zip(r_split, e_split):
            assert r_term == e_term, f"{r} != {e}"
