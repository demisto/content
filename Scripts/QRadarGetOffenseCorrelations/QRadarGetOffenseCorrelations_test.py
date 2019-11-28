import pytest
from QRadarGetOffenseCorrelations import get_query


@pytest.mark.parametrize('bool_val', ["False"])
def test_get_query_cre_name_null_false(bool_val):
    query_from_false = get_query(bool_val)
    assert "\"CRE NAME\" <> NULL" in query_from_false


@pytest.mark.parametrize('bool_val', ["True"])
def test_get_query_cre_name_null_true(bool_val):
    query_from_false = get_query(bool_val)
    assert "\"CRE NAME\" <> NULL" not in query_from_false
