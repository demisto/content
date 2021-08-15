import pytest
from AlexaV2 import Client, rank_to_score, alexa_domain
from CommonServerPython import *  # noqa


def create_client(proxy: bool = False, verify: bool = False, benign: int = 0, threshold: int = 200,
                  reliability: str = DBotScoreReliability.A_PLUS):
    return Client(proxy=proxy, verify=verify, benign=benign, threshold=threshold,
                  reliability=reliability, api_key='', base_url='https://awis.api.alexa.com/api')


def file_to_dct(file: str) -> Dict:
    with open(file, 'r') as f:
        return json.load(f)


client = create_client()

DOMAINS_GOOD_RESULTS = [('google.com', file_to_dct('test_data/google_response.json')),
                        ('google.com', file_to_dct('test_data/404_response.json'))]


@pytest.mark.parametrize('domain, raw_result', DOMAINS_GOOD_RESULTS)
def test_domain_rank(mocker, domain, raw_result):
    """
    Given:
        - A domain to be ranked by Alexa API

    When:
        - running the domain command:
            1. when getting a valid response with an existing domain.
            2. when getting a valid response with an non-existing domain.

    Then:
        - Ensure that the rank the domain got is valid
        - Ensure the context data is valid with the expected outputs.
    """
    mocker.patch.object(client, 'alexa_rank', return_value=raw_result)
    result = alexa_domain(client, {'domain': domain})[0]
    rank_result = result.outputs.get('Rank') if result.outputs.get('Rank') != 'Unknown' else None
    assert demisto.get(raw_result, 'Awis.Results.Result.Alexa.TrafficData.Rank') == rank_result


DOMAINS_BAD_RESULTS = [('xsoar.com', file_to_dct('test_data/negative_rank_response.json')),
                       ('xsoar.com', file_to_dct('test_data/nan_rank_response.json'))]


def test_multi_domains(mocker):
    """
    Given:
        - A list of domains to be ranked by Alexa API

    When:
        - running the domain command on the input

    Then:
        - Ensure that:
          1. The length of the result is the same as the length of the domains list
          2. Valid responses for both of the domains
    """

    domains = 'google.com,xsoar.com'
    raw_res = file_to_dct('test_data/google_response.json')
    mocker.patch.object(client, 'alexa_rank', return_value=raw_res)
    result = alexa_domain(client, {'domain': domains})
    assert len(result) == len(argToList(domains))
    for res in result:
        assert res.outputs.get('Rank') == demisto.get(raw_res, 'Awis.Results.Result.Alexa.TrafficData.Rank')


@pytest.mark.parametrize('domain, raw_result', DOMAINS_BAD_RESULTS)
def test_domain_invalid_rank(mocker, domain, raw_result):
    """
    Given:
        - A domain to be ranked by Alexa API


    When:
        - The API responds with an invalid rank

    Then:
        - Ensure there is an exception
    """
    mocker.patch.object(client, 'alexa_rank', return_value=raw_result)
    with pytest.raises((DemistoException, ValueError)):
        alexa_domain(client, {'domain': domain})


SCORE_TESTS = [(1, 0, 200, DBotScoreReliability.A_PLUS, 1),
               (None, 0, 200, DBotScoreReliability.A_PLUS, 2),
               (0, 0, 200, DBotScoreReliability.A_PLUS, 0),
               (4000, 0, 200, DBotScoreReliability.A_PLUS, 2)]


@pytest.mark.parametrize('rank, threshold, benign, reliability, score', SCORE_TESTS)
def test_rank_to_score(rank, threshold, benign, reliability, score):
    """
    Given:
        - The parameters for the integration, with the rank from the API

    When:
        - After getting the rank, calling the rank_to_Score to get the score based on the parameters and the rank

    Then:
        - Ensure that the score returned corresponds to the algorithm
    """
    context = rank_to_score('google.com', rank, threshold, benign, reliability)
    assert context.dbot_score.score == score


def test_rank_to_score_invalid():
    """
    Given:
        - The parameters for the integration, with the rank from the API

    When:
        - After getting the rank, calling the rank_to_Score to get the score based on the parameters and a rank with is invalid

    Then:
        - Ensure that Exception is being raised
    """

    with pytest.raises(DemistoException):
        rank_to_score('google.com', -1, 0, 200, DBotScoreReliability.A_PLUS)
