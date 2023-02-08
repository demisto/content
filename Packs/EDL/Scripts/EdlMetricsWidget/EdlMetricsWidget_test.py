import demistomock as demisto
from ThreatIntelligenceManagementGetIncidentsPerFeed import get_incidents_per_feed
import re

@pytest.mark.parametrize(
    "instance, output",
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
def record_edl_log_test(mocker):
    mocker.patch.object(demisto, 'get_edl')
    actual_results = get_incidents_per_feed(from_date)
    expected_results = {
        'Test1 Feed': 2,
        'Test2 Feed': 2
    }
    assert actual_results == expected_results

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