import pytest
import demistomock as demisto
from DsSearchQueryTestData import *

@pytest.mark.parametrize('query, output', [("alarmautomatika.com", 2), ("\"alarmautomatika.com\"", 1), ("\"Term 1\"", 1), 
("Term1 AND \"Term 2\" OR (Term3 Term4)", 4), ("frumvarpið \"stæðist ekki\" AND stjórnarskrá", 3), ("$ £", 0), ("  ", 0), ("AND", 1)])
def test_countTerms(query, output):
    from DsSearchQueryArray import count_terms
    assert count_terms(query) == output

def test_createArray(mocker):
    from DsSearchQueryArray import convert_to_ds_query_array
    assert convert_to_ds_query_array(TEST_DATA_URL) == TEST_DATA_URL_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_IP) == TEST_DATA_IP_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_DOMAIN) == TEST_DATA_DOMAIN_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_FILE_SHA1) == TEST_DATA_FILE_SHA1_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_FILE_SHA256) == TEST_DATA_FILE_SHA256_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_FILE_MD5) == TEST_DATA_FILE_MD5_EXPECTED
    assert convert_to_ds_query_array(TEST_DATA_CVE) == TEST_DATA_CVE_EXPECTED

  
