import pytest
from DsSearchQueryTestData import *


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
