import demistomock as demisto
import pytest

import ShowCampaignSimilarityRange


INCIDENT_SIMILARITIES = [{"similarity": 1.000}, {"similarity": 0.946}, {"similarity": 0.977}, {"similarity": 0.999}]


@pytest.mark.parametrize('incident_similarities, expected_header, expected_similarity, pixels', [
    (INCIDENT_SIMILARITIES, 'Similarity Range', '94.6%-100.0%', '24'),
    ([INCIDENT_SIMILARITIES[2]], 'Similarity', '97.7%', '24'),
    ([], 'Similarity', 'No incident similarities were found.', '20')
])
def test_show_campaign_similarity_range(mocker, incident_similarities, expected_header, expected_similarity, pixels):
    """
    Given:
        - Campaign incidents.
    When:
        - Running the show campaign similarity range script main function.
    Then:
        - Ensure the correct similarity range is appear in the html format.
    """
    mocker.patch.object(demisto, 'get', return_value=incident_similarities)
    mocker.patch.object(demisto, 'results')

    ShowCampaignSimilarityRange.main()
    res = demisto.results.call_args[0][0]['Contents']
    expected_result = f"<div style='text-align:center; font-size:17px; padding: 15px;'>{expected_header}</br> " \
                      f"<div style='font-size:{pixels}px;'> {expected_similarity} </div></div>"

    assert expected_result == res
