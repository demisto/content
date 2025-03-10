import json
import io
import freezegun
import pytest
from CommonServerPython import DemistoException


expected_hr_twitter_user_get = (
    "### Twitter user get results:"
    "\n|Name|User name|Created At|Description|Followers Count|Tweet Count|Verified|\n"
    "|---|---|---|---|---|---|---|\n|"
    " Some_name | Some_user_name | 2024-11-09T09:55:45.000Z | Some_description | 12 | 15 | True |\n"
)


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


test_data = util_load_json("test_data/test_data.json")


def side_effect_twitter_tweet_search(method, url_suffix, headers, params, ok_codes):
    if int(params.get("max_results")) and (int(params.get("max_results")) < 10 or int(params.get("max_results")) > 100):
        raise DemistoException(
            message=f"The max_results query parameter value [{params.get('max_results')}] is not between 10 and 100",
            res={
                "errors": [
                    {
                        "parameters": {"max_results": f"[{params.get('max_results')}]"},
                        "message": f"The max_results query parameter value [{params.get('max_results')}] "
                        "is not between 10 and 100",
                    }
                ],
                "title": "Invalid Request",
                "detail": "One or more parameters to your request was invalid.",
                "type": "invalid-request",
            },
        )
    if params.get("start_time") and params.get("end_time"):
        return test_data["search_tweets_response_dates"]
    return test_data["search_tweets_response"]


@pytest.mark.parametrize(
    "limit, start_time, end_time ,expected_output\
                         ,expected_human_readable, expected_raw",
    [
        (
            10,
            "",
            "",
            test_data["search_tweet_output"],
            test_data["search_tweets_human_readable"],
            test_data["search_tweets_response"],
        ),
        (
            3,
            "",
            "",
            test_data["search_tweet_output"],
            test_data["search_tweets_human_readable"],
            test_data["search_tweets_response"],
        ),
        (
            200,
            "",
            "",
            test_data["search_tweet_output"],
            test_data["search_tweets_human_readable"],
            test_data["search_tweets_response"],
        ),
        (
            10,
            "2020-11-10T00:00:00Z",
            "2020-11-17T00:00:00Z",
            test_data["expected_output_dates"],
            "### Tweets search results:"
            "\n|Tweet ID|Text|Created At|Author Name|Author Username|Likes Count|Attachments URL|\n|"
            "---|---|---|---|---|---|---|\n|"
            " 2020202020202020202 | some_tweet_text_1 | 2020-11-10T00:00:00.000Z | name_1 | username_1 | 0 |  |\n|"
            " 2929292929292929292 | some_tweet_text_2 | 2020-11-11T00:00:00.000Z | name_2 | username_2 | 0 |  |\n|"
            " 2828282828282828282 | some_tweet_text_3 | 2020-11-12T00:00:00.000Z | name_3 | username_3 | 0 |"
            " https://url.jpg,<br>https://url.jpg,<br>https://url.jpg,<br>https://url.jpg |\n",
            test_data["search_tweets_response_dates"],
        ),
    ],
)
def test_twitter_tweet_search_command(
    mocker, limit, start_time, end_time, expected_output, expected_human_readable, expected_raw
):
    """
    Given:
        - API response from twitter.
    When:
        - twitter-tweet-search command is executed.
    Then:
        - Validate readable output, outputs and raw response.
    """
    from Twitterv2 import Client, twitter_tweet_search_command

    client = Client(base_url="some_base_url", verify=False, headers={"Authorization": "Bearer 000"})
    args = {
        "query": "some_tweet_text",
        "start_time": start_time,
        "end_time": end_time,
        "limit": limit,
        "next_token": "",
    }
    mocker.patch.object(Client, "_http_request", side_effect=side_effect_twitter_tweet_search)
    if limit < 10 or limit > 100:
        with pytest.raises(DemistoException):
            result = twitter_tweet_search_command(client, args)
    else:
        result = twitter_tweet_search_command(client, args)
        assert result[0].outputs == expected_output
        assert result[0].readable_output == expected_human_readable
        assert result[0].raw_response == expected_raw


@pytest.mark.parametrize(
    "response, expected_output, expected_raw",
    [(test_data["user_get_response"], test_data["result_user_get_response"], test_data["user_get_response"])],
)
def test_twitter_user_get_command(mocker, response, expected_output, expected_raw):
    """
    Given:
        - API response from twitter.
    When:
        - twitter-user-get command is executed.
    Then:
        - Validate readable output, outputs and raw response.
    """
    from Twitterv2 import Client, twitter_user_get_command

    client = Client(base_url="some_base_url", verify=False, headers={"Authorization": "Bearer 000"})
    args = {
        "user_name": "some_username",
        "return_pinned_tweets": "True",
        "limit": "10",
    }
    mocker.patch.object(Client, "_http_request", return_value=response)
    result = twitter_user_get_command(client, args)

    assert result.readable_output == expected_hr_twitter_user_get
    assert result.outputs == expected_output
    assert result.raw_response == expected_raw


@freezegun.freeze_time("2020-11-25T11:57:28Z")
@pytest.mark.parametrize(
    "date, expected_result",
    [
        ("7 Days ago", "2020-11-18T11:57:28Z"),
        ("2020-11-18T13:57:28Z", "2020-11-18T13:57:28Z"),
        ("2020-11-18", "2020-11-18T00:00:00Z"),
        ("2020/11/18", "2020-11-18T00:00:00Z"),
        ("18/11/2020", "2020-11-18T00:00:00Z"),
    ],
)
def test_date_to_iso_format(date, expected_result):
    """
    Tests date_to_iso_format
    Given:
        - date representation
    When:
        - calling date_to_iso_format
    Then:
        - return an ISO format
    """
    from Twitterv2 import date_to_iso_format

    result = date_to_iso_format(date)
    assert result == expected_result


@pytest.mark.parametrize(
    "response, expected_result", [(test_data["search_tweets_response"], test_data["expected_output_create_context_search"])]
)
def test_create_context_data_search_tweets(response, expected_result):
    """
    Tests create_context_data_search_tweets
    Given:
        - list of nested dictionaries
    When:
        - calling create_context_data_search_tweets
    Then:
        - return a list dictionaries according to the required context format
    """
    from Twitterv2 import create_context_data_search_tweets

    result, next_token = create_context_data_search_tweets(response)
    assert result == expected_result
    assert next_token == "some_token"


@pytest.mark.parametrize("response, expected_result", [(test_data["user_get_response"], test_data["result_user_get_response"])])
def test_create_context_data_get_user(response, expected_result):
    """
    Tests create_context_data_get_user
    Given:
        - list of nested dictionaries
    When:
        - calling create_context_data_get_user
    Then:
        - return a list dictionaries according to the required context format
    """
    from Twitterv2 import create_context_data_get_user

    result = create_context_data_get_user(response, "true")
    assert result == expected_result
