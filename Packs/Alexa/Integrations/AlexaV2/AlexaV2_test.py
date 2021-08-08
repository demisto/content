import pytest
from AlexaV2 import *  # noqa


def create_client(proxy: bool = False, verify: bool = False, benign: int = 0, threshold: int = 200,
                  reliability: str = DBotScoreReliability.A_PLUS):
    return Client(proxy=proxy, verify=verify, benign=benign, threshold=threshold,
                  reliability=reliability, api_key='', base_url='')


def file_to_dct(file: str) -> Dict:
    with open(file, 'r') as f:
        return json.load(f)


client = create_client()

DOMAINS_GOOD_RESULTS = [('google.com', file_to_dct('google_response.json')),
                        ('google.com', file_to_dct('404_response.json'))]


@pytest.mark.parametrize('domain, raw_result', DOMAINS_GOOD_RESULTS)
def test_domain_rank(mocker, domain, raw_result):
    """
    Given:
        - domains, valid or 404

    When:
        - In the beginning of the domain command

    Then:
        - Returns the rank of google
    """
    mocker.patch.object(client, 'alexa_rank', return_value=raw_result)
    result = alexa_domain(client, {'domain': domain})
    assert result.outputs.get('Rank') == demisto.get(raw_result, 'Awis.Results.Result.Alexa.TrafficData.Rank')


DOMAINS_BAD_RESULTS = [('demisto.com', file_to_dct('negative_rank_response.json')),
                       ('demisto.com', file_to_dct('nan_rank_response.json'))]


@pytest.mark.parametrize('domain, raw_result', DOMAINS_BAD_RESULTS)
def test_domain_invalid_rank(mocker, domain, raw_result):
    """
    Given:
        - domains, which received invalid rank (which we shouldn't receive)

    When:
        - In the beginning of the domain command

    Then:
        - Wait for demisto Exception or Value Error
    """
    mocker.patch.object(client, 'alexa_rank', return_value=raw_result)
    with pytest.raises(DemistoException, ValueError):
        alexa_domain(client, {'domain': domain})


SCORE_TESTS = [(1, 0, 200, DBotScoreReliability.A_PLUS, 1, 'good'),
               (None, 0, 200, DBotScoreReliability.A_PLUS, 2, 'suspicious')]


@pytest.mark.parametrize('rank, threshold, benign, reliability, score, score_text', SCORE_TESTS)
def test_rank_to_score(rank, threshold, benign, reliability, score, score_text):
    """
    Given:
        - parameters for rank to score conversion

    When:
        - In the middle of the domain command, rank_to_score function

    Then:
        - Returns the context of the dbot and the score text
    """

    context, score_text_res = rank_to_score('google.com', rank, threshold, benign, reliability)
    assert context.dbot_score.score == score and score_text == score_text_res


def test_rank_to_score_invalid():
    """
    Given:
        - parameters for rank to score conversion, which is invalid

    When:
        - In the middle of the domain command, rank_to_score function

    Then:
        - Get a demisto exception
    """

    with pytest.raises(DemistoException):
        rank_to_score('google.com', -1, 0, 200, DBotScoreReliability.A_PLUS)
