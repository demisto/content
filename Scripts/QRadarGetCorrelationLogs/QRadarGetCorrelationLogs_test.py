from QRadarGetCorrelationLogs import get_query


def test_get_query_cre_name_null_false():
    query_from_false = get_query("False")
    assert "\"CRE Name\" <> NULL" in query_from_false


def test_get_query_cre_name_null_true():
    query_from_false = get_query("True")
    assert "\"CRE Name\" <> NULL" not in query_from_false
