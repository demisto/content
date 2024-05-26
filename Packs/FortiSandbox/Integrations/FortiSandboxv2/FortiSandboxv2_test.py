import json
import os
import unittest.mock
from typing import Any

import CommonServerPython
import FortiSandboxv2
import pytest

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com"
API_URL = CommonServerPython.urljoin(BASE_URL, "jsonrpc/")

""" Utils """


def load_mock_response(file_name: str) -> dict[str, Any]:
    """Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


""" Fixtures """


@pytest.fixture()
def mock_client() -> FortiSandboxv2.Client:
    """
    Establish a mock connection to the client with a username and password.

    Returns:
        Client: Mock connection to client.
    """
    return FortiSandboxv2.Client(
        base_url=BASE_URL,
        username="Pokemon",
        password="Pikachu",
    )


""" Helper Tests """


def test_bool_to_int():
    """Test the bool_to_int function.

    Ensure:
    - False is converted to 0.
    - True is converted to 1.
    """
    assert FortiSandboxv2.bool_to_int(False) == 0
    assert FortiSandboxv2.bool_to_int(True) == 1


def test_bool_to_str():
    """Test the bool_to_str function.

    Ensure:
    - False is converted to "0".
    - True is converted to "1".
    """
    assert FortiSandboxv2.bool_to_str(False) == "0"
    assert FortiSandboxv2.bool_to_str(True) == "1"


@pytest.mark.parametrize(
    "indicator,indicator_type,score,rating,detail_url",
    [
        ("pikachu.exe", CommonServerPython.DBotScoreType.FILE, -1, None, "hello"),
        ("pikachu.exe", CommonServerPython.DBotScoreType.FILE, None, "Unknown", None),
        ("pikachu.exe", CommonServerPython.DBotScoreType.FILE, None, ["Unknown"], None),
        ("pikachu.exe", CommonServerPython.DBotScoreType.FILE, None, None, "hello"),
        ("pikachu.com", CommonServerPython.DBotScoreType.URL, -1, None, "hello"),
    ],
)
def test_build_dbot_score(
    indicator: str,
    indicator_type: str,
    score: int | None,
    rating: list[str] | str | None,
    detail_url: str | None,
):
    """Test the build_dbot_score function.

    Ensure:
    - The indicator is set to the expected indicator value.
    - The indicator type is set to the expected indicator type.
    - The score is set to Common.DBotScore.NONE.
    - The reliability is set to Common.DBotScoreReliability.C.
    - The message is set to the detail URL.

    Args:
        indicator (str): The indicator value.
        indicator_type (str): The type of the indicator.
        score (int | None): The score value.
        rating (list[str] | str | None): The rating value.
        detail_url (str | None): The detail URL.
    """
    dbot_score = FortiSandboxv2.build_dbot_score(
        indicator=indicator,
        indicator_type=indicator_type,
        score=score,
        rating=rating,
        detail_url=detail_url,
    )

    assert dbot_score.indicator == indicator
    assert dbot_score.indicator_type == indicator_type
    assert dbot_score.score == CommonServerPython.Common.DBotScore.NONE
    assert dbot_score.reliability == CommonServerPython.DBotScoreReliability.C
    assert dbot_score.message == detail_url


def test_build_relationship():
    """Test the build_relationship function.

    Ensure:
    - The entity is set to the expected entity value.
    """
    entity_type = CommonServerPython.FeedIndicatorType.File
    entity = "pikachu.exe"
    malware = "pikachu"

    output = FortiSandboxv2.build_relationship(
        entity_type=entity_type,
        entity=entity,
        malware=malware,
    )
    expected_result = CommonServerPython.EntityRelationship(
        name=CommonServerPython.EntityRelationship.Relationships.INDICATOR_OF,
        entity_a=entity,
        entity_a_type=entity_type,
        entity_b=malware,
        entity_b_type=CommonServerPython.FeedIndicatorType.Malware,
        reverse_name=CommonServerPython.EntityRelationship.Relationships.INDICATED_BY,
        brand="FortiSandbox",
        source_reliability=CommonServerPython.DBotScoreReliability.C,
    )
    assert output.to_context() == expected_result.to_context()


@pytest.mark.parametrize(
    "data,url,file_hash,expected_result",
    [
        (
            {
                "score": 3,
                "malware_name": "thunderbolt",
                "detail_url": "https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=url-csearch",
                "download_url": "d3d3LnBva2Vtb24uY29t",
                "category": "pokemon",
            },
            None,
            None,
            CommonServerPython.Common.URL(
                dbot_score=CommonServerPython.Common.DBotScore(
                    indicator="www.pokemon.com",
                    indicator_type=CommonServerPython.DBotScoreType.URL,
                    score=CommonServerPython.Common.DBotScore.SUSPICIOUS,
                    reliability=FortiSandboxv2.RELIABILITY,
                    message="https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=url-csearch",
                ),
                url="www.pokemon.com",
                category="pokemon",
                malware_family=["thunderbolt"],
                relationships=[
                    CommonServerPython.EntityRelationship(
                        name=CommonServerPython.EntityRelationship.Relationships.INDICATOR_OF,
                        entity_a="www.pokemon.com",
                        entity_a_type=CommonServerPython.FeedIndicatorType.URL,
                        entity_b="thunderbolt",
                        entity_b_type=CommonServerPython.FeedIndicatorType.Malware,
                        reverse_name=CommonServerPython.EntityRelationship.Relationships.INDICATED_BY,
                        brand="FortiSandbox",
                        source_reliability=FortiSandboxv2.RELIABILITY,
                    )
                ],
            ),
        ),
        (
            {
                "rating": "High Risk",
                "malware_name": "N/A",
                "detail_url": "https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=url-csearch",
                "url": "www.pokemon.com",
                "category": "NotApplicable",
            },
            None,
            None,
            CommonServerPython.Common.URL(
                dbot_score=CommonServerPython.Common.DBotScore(
                    indicator="www.pokemon.com",
                    indicator_type=CommonServerPython.DBotScoreType.URL,
                    score=CommonServerPython.Common.DBotScore.BAD,
                    reliability=FortiSandboxv2.RELIABILITY,
                    message="https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=url-csearch",
                ),
                url="www.pokemon.com",
            ),
        ),
        (
            {
                "rating": "High Risk",
            },
            "www.pokemon.com",
            None,
            CommonServerPython.Common.URL(
                dbot_score=CommonServerPython.Common.DBotScore(
                    indicator="www.pokemon.com",
                    indicator_type=CommonServerPython.DBotScoreType.URL,
                    score=CommonServerPython.Common.DBotScore.BAD,
                    reliability=FortiSandboxv2.RELIABILITY,
                ),
                url="www.pokemon.com",
            ),
        ),
        (
            {
                "score": 3,
                "malware_name": "thunderbolt",
                "detail_url": "https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=file-csearch",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "sha1": "0000000000000000000000000000000000000000",
                "file_name": "pikachu.exe",
            },
            None,
            None,
            CommonServerPython.Common.File(
                dbot_score=CommonServerPython.Common.DBotScore(
                    indicator="0000000000000000000000000000000000000000000000000000000000000000",
                    indicator_type=CommonServerPython.DBotScoreType.FILE,
                    score=CommonServerPython.Common.DBotScore.SUSPICIOUS,
                    reliability=FortiSandboxv2.RELIABILITY,
                    message="https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=file-csearch",
                ),
                name="pikachu.exe",
                extension="exe",
                malware_family=["thunderbolt"],
                sha1="0000000000000000000000000000000000000000",
                sha256="0000000000000000000000000000000000000000000000000000000000000000",
                relationships=[
                    CommonServerPython.EntityRelationship(
                        name=CommonServerPython.EntityRelationship.Relationships.INDICATOR_OF,
                        entity_a="0000000000000000000000000000000000000000000000000000000000000000",
                        entity_a_type=CommonServerPython.FeedIndicatorType.File,
                        entity_b="thunderbolt",
                        entity_b_type=CommonServerPython.FeedIndicatorType.Malware,
                        reverse_name=CommonServerPython.EntityRelationship.Relationships.INDICATED_BY,
                        brand="FortiSandbox",
                        source_reliability=FortiSandboxv2.RELIABILITY,
                    )
                ],
            ),
        ),
        (
            {
                "rating": ["High Risk"],
                "malware_name": ["thunderbolt", "N/A"],
                "detail_url": "https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=file-csearch",
            },
            None,
            "0000000000000000000000000000000000000000000000000000000000000000",
            CommonServerPython.Common.File(
                dbot_score=CommonServerPython.Common.DBotScore(
                    indicator="0000000000000000000000000000000000000000000000000000000000000000",
                    indicator_type=CommonServerPython.DBotScoreType.FILE,
                    score=CommonServerPython.Common.DBotScore.BAD,
                    reliability=FortiSandboxv2.RELIABILITY,
                    message="https://0.0.0.0/job-detail/?sid=0&jid=0&req_type=file-csearch",
                ),
                malware_family=["thunderbolt"],
                sha256="0000000000000000000000000000000000000000000000000000000000000000",
                relationships=[
                    CommonServerPython.EntityRelationship(
                        name=CommonServerPython.EntityRelationship.Relationships.INDICATOR_OF,
                        entity_a="0000000000000000000000000000000000000000000000000000000000000000",
                        entity_a_type=CommonServerPython.FeedIndicatorType.File,
                        entity_b="thunderbolt",
                        entity_b_type=CommonServerPython.FeedIndicatorType.Malware,
                        reverse_name=CommonServerPython.EntityRelationship.Relationships.INDICATED_BY,
                        brand="FortiSandbox",
                        source_reliability=FortiSandboxv2.RELIABILITY,
                    )
                ],
            ),
        ),
    ],
)
def test_build_indicator(
    data: dict[str, Any],
    url: str | None,
    file_hash: str | None,
    expected_result: CommonServerPython.Common.Indicator,
):
    """Test the build_indicator function.

    Ensure:
    - The indicator is set to the expected indicator value.

    Args:
        data (dict[str, Any]): The data to build the indicator from.
        url (str | None): The URL to build the indicator from.
        file_hash (str | None): The file hash to build the indicator from.
        expected_result (CommonServerPython.Common.Indicator): The expected indicator.
    """
    indicator = FortiSandboxv2.build_indicator(data, url, file_hash)
    assert indicator.to_context() == expected_result.to_context()


@pytest.mark.parametrize(
    "args,expected_result",
    [
        (
            {"urls": ["https://pikachu.com", "www.pokemon.com"]},
            ("dXJsc19mb3JfdXBsb2FkXzE2MDk0NTkyMDAudHh0", "aHR0cHM6Ly9waWthY2h1LmNvbQp3d3cucG9rZW1vbi5jb20="),
        ),
        (
            {"entry_id": "123"},
            ("cGlrYWNodS5leGU=", "aHR0cHM6Ly9waWthY2h1LmNvbQp3d3cucG9rZW1vbi5jb20="),
        ),
    ],
)
@unittest.mock.patch("FortiSandboxv2.time.time", return_value=1609459200)
@unittest.mock.patch("FortiSandboxv2.demisto.getFilePath", return_value={"path": "/path", "name": "pikachu.exe"})
def test_prepare_submission_content(
    mocked_time,
    mocked_get_file_path,
    args: dict[str, Any],
    expected_result: tuple[str, str],
):
    """Test the prepare_submission_content function.

    Ensure:
    - The file name and content is set to the expected file name and content.

    Args:
        mocked_time (MagicMock): A mock for the `time.time` function to return a fixed timestamp, ensuring
            the generated file name's timestamp component is predictable for the test.
        mocked_get_file_path (MagicMock): A mock for the `demisto.getFilePath` function to simulate retrieving
            the file path and name when an `entry_id` is provided, allowing for
            testing of the file upload functionality without accessing the file system.
        args (dict[str, Any]): The arguments to pass to the function.
        expected_result (tuple[str, str]): The expected result.
    """
    mocked_open = unittest.mock.mock_open(read_data="https://pikachu.com\nwww.pokemon.com")

    with unittest.mock.patch("builtins.open", mocked_open):
        file_name, content = FortiSandboxv2.prepare_submission_content(args)

    assert (file_name, content) == expected_result


@pytest.mark.parametrize(
    "args",
    [
        ({}),
        ({"entry_id": "123", "urls": ["https://pikachu.com"]}),
    ],
)
def test_prepare_submission_content_error(args: dict[str, Any]):
    """Test the prepare_submission_content function with an error.

    Ensure:
    - A DemistoException is raised.

    Args:
        args (dict[str, Any]): The arguments to pass to the function.
    """
    with pytest.raises(CommonServerPython.DemistoException):
        FortiSandboxv2.prepare_submission_content(args)


@pytest.mark.parametrize(
    "args,integration_context,file_names,expected_context_list,expected_poll_result",
    [
        (
            {"sid": "123"},
            {},
            [
                "job_list_empty.json",
            ],
            [
                {
                    "total_jids": 0,
                    "fetched_jids": [],
                    "remaining_jids": [],
                    "jid_to_raw_response": {},
                }
            ],
            CommonServerPython.PollResult(
                response=None,
                continue_to_poll=True,
                args_for_next_run={"sid": "123"},
                partial_result=CommonServerPython.CommandResults(
                    readable_output="## No jobs were created yet for the submission 123."
                ),
            ),
        ),
        (
            {"sid": "123"},
            {
                "total_jids": 3,
                "fetched_jids": ["000"],
                "remaining_jids": ["111"],
                "jid_to_raw_response": {
                    "000": load_mock_response("job_verdict.json"),
                },
            },
            [
                "job_list_done.json",
                "job_verdict.json",
                "job_verdict.json",
            ],
            [
                {
                    "total_jids": 3,
                    "fetched_jids": ["111", "222", "000"],
                    "remaining_jids": [],
                },
                {},
            ],
            CommonServerPython.PollResult(
                response=[
                    CommonServerPython.CommandResults(
                        indicator=CommonServerPython.Common.URL(
                            dbot_score=CommonServerPython.Common.DBotScore(
                                indicator="www.pokemon.com",
                                indicator_type=CommonServerPython.DBotScoreType.URL,
                                score=CommonServerPython.Common.DBotScore.GOOD,
                                reliability=FortiSandboxv2.RELIABILITY,
                                message="https://pikachu/job-detail/?sid=456&jid=123&req_type=url-csearch",
                            ),
                            url="www.pokemon.com",
                        ),
                    ),
                    CommonServerPython.CommandResults(
                        indicator=CommonServerPython.Common.URL(
                            dbot_score=CommonServerPython.Common.DBotScore(
                                indicator="www.pokemon.com",
                                indicator_type=CommonServerPython.DBotScoreType.URL,
                                score=CommonServerPython.Common.DBotScore.GOOD,
                                reliability=FortiSandboxv2.RELIABILITY,
                                message="https://pikachu/job-detail/?sid=456&jid=123&req_type=url-csearch",
                            ),
                            url="www.pokemon.com",
                        ),
                    ),
                    CommonServerPython.CommandResults(
                        indicator=CommonServerPython.Common.URL(
                            dbot_score=CommonServerPython.Common.DBotScore(
                                indicator="www.pokemon.com",
                                indicator_type=CommonServerPython.DBotScoreType.URL,
                                score=CommonServerPython.Common.DBotScore.GOOD,
                                reliability=FortiSandboxv2.RELIABILITY,
                                message="https://pikachu/job-detail/?sid=456&jid=123&req_type=url-csearch",
                            ),
                            url="www.pokemon.com",
                        ),
                    ),
                ],
                continue_to_poll=False,
            ),
        ),
    ],
)
def test_poll_job_submissions(
    requests_mock,
    mock_client: FortiSandboxv2.Client,
    args: dict[str, Any],
    integration_context: dict[str, Any],
    file_names: list[str],
    expected_context_list: list[dict[str, Any]],
    expected_poll_result: CommonServerPython.PollResult,
):
    """Test the poll_job_submissions function.

    Ensure:
    - The integration context is set to the expected integration context.
    - The poll result is set to the expected poll result.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client.
        args (dict[str, Any]): The arguments to pass to the function.
        integration_context (dict[str, Any]): The integration context to patch.
        file_names (list[str]): The file names for the mocked responses.
        expected_context_list (list[dict[str, Any]]): A list of the expected integration context.
        expected_poll_result (CommonServerPython.PollResult): The expected poll result.
    """
    requests_mock.post(
        API_URL,
        [{"json": load_mock_response(file_name)} for file_name in file_names],
    )

    with (
        unittest.mock.patch("FortiSandboxv2.get_integration_context", return_value=integration_context),
        unittest.mock.patch("FortiSandboxv2.set_integration_context") as mock_set_integration_context,
    ):
        poll_result = FortiSandboxv2.poll_job_submissions(client=mock_client, args=args)

        for call_args, expected_context in zip(mock_set_integration_context.call_args_list, expected_context_list):
            args = call_args.args[0]
            assert set(args.get("fetched_jids", [])) == set(expected_context.get("fetched_jids", []))
            assert set(args.get("remaining_jids", [])) == set(expected_context.get("remaining_jids", []))
            assert args.get("total_jids") == expected_context.get("total_jids")

    assert poll_result.continue_to_poll == expected_poll_result.continue_to_poll
    assert poll_result.args_for_next_run == expected_poll_result.args_for_next_run

    if poll_result.response or expected_poll_result.response:
        for actual_response, expected_response in zip(poll_result.response, expected_poll_result.response):
            assert actual_response.indicator.to_context() == expected_response.indicator.to_context()

    if poll_result.partial_result or expected_poll_result.partial_result:
        assert poll_result.partial_result.to_context() == expected_poll_result.partial_result.to_context()


""" Command Tests """


def test_test_module(requests_mock, mock_client: FortiSandboxv2.Client):
    """Test the test_module function.

    Ensure:
    - The result is set to "ok".

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client.
    """
    requests_mock.post(API_URL, json={"result": {"status": {"code": 0}}})
    result = FortiSandboxv2.test_module(client=mock_client)
    assert result == "ok"


@pytest.mark.parametrize(
    "file_name,expected_outputs",
    [
        (
            "url_rating_known.json",
            [
                CommonServerPython.Common.URL(
                    dbot_score=CommonServerPython.Common.DBotScore(
                        indicator="https://www.pokemon.com",
                        indicator_type=CommonServerPython.DBotScoreType.URL,
                        score=CommonServerPython.Common.DBotScore.GOOD,
                        reliability=FortiSandboxv2.RELIABILITY,
                        message="",
                    ),
                    url="https://www.pokemon.com",
                ),
                CommonServerPython.Common.URL(
                    dbot_score=CommonServerPython.Common.DBotScore(
                        indicator="http://pikachu.com",
                        indicator_type=CommonServerPython.DBotScoreType.URL,
                        score=CommonServerPython.Common.DBotScore.BAD,
                        reliability=FortiSandboxv2.RELIABILITY,
                        message="",
                    ),
                    url="http://pikachu.com",
                ),
            ],
        ),
        (
            "url_rating_unknown.json",
            [
                CommonServerPython.create_indicator_result_with_dbotscore_unknown(
                    indicator="https://www.charizard.com",
                    indicator_type=CommonServerPython.DBotScoreType.URL,
                    reliability=FortiSandboxv2.RELIABILITY,
                ).indicator,
                CommonServerPython.create_indicator_result_with_dbotscore_unknown(
                    indicator="http://squirtle.com",
                    indicator_type=CommonServerPython.DBotScoreType.URL,
                    reliability=FortiSandboxv2.RELIABILITY,
                ).indicator,
            ],
        ),
    ],
)
def test_url_command(
    requests_mock,
    mock_client: FortiSandboxv2.Client,
    file_name: str,
    expected_outputs: list[CommonServerPython.Common.Indicator],
):
    """Test the url_command function for generic reputation.

    Ensure:
    - The indicator is set to the expected indicator value.
    - The raw response is set to the expected raw response.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
        file_name (str): The file name for the mocked response.
        expected_outputs (list[CommonServerPython.Common.Indicator]): expected output for assertion.
    """
    mock_response = load_mock_response(file_name)
    requests_mock.post(API_URL, json=mock_response)

    command_results = FortiSandboxv2.url_command(mock_client, {"url": "www.pokemon.com"})

    for command_result, expected_output in zip(command_results, expected_outputs):
        assert command_result.indicator.to_context() == expected_output.to_context()
        assert command_result.raw_response == mock_response


@pytest.mark.parametrize(
    "file_name,expected_outputs",
    [
        (
            "file_verdict_known.json",
            [
                CommonServerPython.Common.File(
                    dbot_score=CommonServerPython.Common.DBotScore(
                        indicator="0000000000000000000000000000000000000000000000000000000000000000",
                        indicator_type=CommonServerPython.DBotScoreType.FILE,
                        score=CommonServerPython.Common.DBotScore.BAD,
                        reliability=FortiSandboxv2.RELIABILITY,
                        message="",
                    ),
                    sha256="0000000000000000000000000000000000000000000000000000000000000000",
                    malware_family=["pokemon"],
                    name="pikachu.exe",
                    extension="exe",
                    relationships=[
                        CommonServerPython.EntityRelationship(
                            name=CommonServerPython.EntityRelationship.Relationships.INDICATOR_OF,
                            entity_a="0000000000000000000000000000000000000000000000000000000000000000",
                            entity_a_type=CommonServerPython.FeedIndicatorType.File,
                            entity_b="pokemon",
                            entity_b_type=CommonServerPython.FeedIndicatorType.Malware,
                            reverse_name=CommonServerPython.EntityRelationship.Relationships.INDICATED_BY,
                            brand="FortiSandbox",
                            source_reliability=FortiSandboxv2.RELIABILITY,
                        )
                    ],
                ),
            ],
        ),
        (
            "file_verdict_unknown.json",
            [
                CommonServerPython.create_indicator_result_with_dbotscore_unknown(
                    indicator="0000000000000000000000000000000000000000000000000000000000000000",
                    indicator_type=CommonServerPython.DBotScoreType.FILE,
                    reliability=FortiSandboxv2.RELIABILITY,
                ).indicator,
            ],
        ),
    ],
)
def test_file_command(
    requests_mock,
    mock_client: FortiSandboxv2.Client,
    file_name: str,
    expected_outputs: list[CommonServerPython.Common.Indicator],
):
    """Test the file_command function for generic reputation.

    Ensure:
    - The indicator is set to the expected indicator value.
    - The raw response is set to the expected raw response.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
        file_name (str | None): The file name for the mocked response.
        expected_outputs (list[CommonServerPython.Common.Indicator]): expected output for assertion.
    """
    sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
    mock_response = load_mock_response(file_name)
    requests_mock.post(API_URL, json=mock_response)

    command_results = FortiSandboxv2.file_command(mock_client, {"file": sha256})

    for command_result, expected_output in zip(command_results, expected_outputs):
        assert command_result.indicator.to_context() == expected_output.to_context()
        assert command_result.raw_response == mock_response


def test_submission_file_upload_command_error(mock_client: FortiSandboxv2.Client):
    """Test the submission_file_upload_command function with an error.

    Ensure:
    - A DemistoException is raised.

    Args:
        mock_client (FortiSandboxv2.Client): Mocked client.
    """
    with pytest.raises(CommonServerPython.DemistoException):
        FortiSandboxv2.submission_file_upload_command({"comment": "0" * 256}, mock_client)


@pytest.mark.parametrize(
    "args",
    [
        ({"comment": "0" * 256}),
        ({"depth": "6"}),
        ({"process_timeout": "29"}),
    ],
)
def test_submission_url_upload_command_error(mock_client: FortiSandboxv2.Client, args: dict[str, Any]):
    """Test the submission_url_upload_command function with an error.

    Ensure:
    - A DemistoException is raised.

    Args:
        mock_client (FortiSandboxv2.Client): Mocked client.
        args (dict[str, Any]): The arguments to pass to the function.
    """
    with pytest.raises(CommonServerPython.DemistoException):
        FortiSandboxv2.submission_url_upload_command(args, mock_client)


def test_submission_cancel_command(requests_mock, mock_client: FortiSandboxv2.Client):
    """Test the submission_cancel_command function.

    Ensure:
    - The readable output is set to the expected readable output.
    - The raw response is set to the expected raw response.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
    """
    sid = "123"
    mock_raw_response = {"result": {"status": {"code": 0}}}
    requests_mock.post(API_URL, json=mock_raw_response)

    command_results = FortiSandboxv2.submission_cancel_command(mock_client, {"id": sid})

    assert command_results.readable_output == f"## The cancellation of the submission {sid} was successfully sent."
    assert command_results.raw_response == mock_raw_response


def test_submission_job_verdict_command(requests_mock, mock_client: FortiSandboxv2.Client):
    """Test the submission_job_verdict_command function.

    Ensure:
    - The command results is set to the expected command results value.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
    """
    url = "www.pokemon.com"
    jid = "123"
    mock_raw_response = load_mock_response("job_verdict.json")
    indicator = CommonServerPython.Common.URL(
        dbot_score=CommonServerPython.Common.DBotScore(
            indicator=url,
            indicator_type=CommonServerPython.DBotScoreType.URL,
            score=CommonServerPython.Common.DBotScore.GOOD,
            reliability=FortiSandboxv2.RELIABILITY,
            message="https://pikachu/job-detail/?sid=456&jid=123&req_type=url-csearch",
        ),
        url=url,
    )
    requests_mock.post(API_URL, json=mock_raw_response)

    command_results = FortiSandboxv2.submission_job_verdict_command(mock_client, {"id": jid})

    mock_raw_response["result"]["data"]["name"] = url

    assert command_results.outputs_prefix == "FortiSandbox.Submission"
    assert command_results.outputs_key_field == "jid"
    assert command_results.outputs == {**mock_raw_response["result"]["data"], "name": url}
    assert command_results.readable_output.startswith(f"### The verdict for the job {jid}:")
    assert command_results.raw_response == mock_raw_response
    assert command_results.indicator.to_context() == indicator.to_context()


def test_submission_job_list_command(requests_mock, mock_client: FortiSandboxv2.Client):
    """Test the submission_job_list_command function.

    Ensure:
    - The command results is set to the expected command results value.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
    """
    sid = "123"
    mock_raw_response = load_mock_response("job_list_done.json")
    requests_mock.post(API_URL, json=mock_raw_response)

    command_results = FortiSandboxv2.submission_job_list_command(mock_client, {"id": sid})

    assert command_results.outputs_prefix == "FortiSandbox.Submission"
    assert command_results.outputs_key_field == "jid"
    assert command_results.outputs == [{"sid": sid, "jid": jid} for jid in ["000", "111", "222"]]
    assert command_results.readable_output.startswith(f"### The submission {sid} job IDs:")
    assert command_results.raw_response == mock_raw_response


@pytest.mark.parametrize(
    "identifier",
    ["123", "0000000000000000000000000000000000000000000000000000000000000000"],
)
def test_submission_job_report_command(requests_mock, mock_client: FortiSandboxv2.Client, identifier: str):
    """Test the submission_job_report_command function.

    Ensure:
    - The file result is set to the expected file result value.
    - The file content is set to the expected file content value.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (FortiSandboxv2.Client): Mocked client
        identifier (str): The identifier for the job.
    """
    mock_raw_response = load_mock_response("job_report.json")
    requests_mock.post(API_URL, json=mock_raw_response)

    # Use mock_open to simulate file operations
    mock_open = unittest.mock.mock_open()
    with (
        unittest.mock.patch("builtins.open", mock_open),
        unittest.mock.patch("FortiSandboxv2.demisto.uniqueFile", return_value="mock_file_id"),
    ):
        file_result = FortiSandboxv2.submission_job_report_command(mock_client, {"identifier": identifier})
        handle = mock_open()

        assert file_result == {
            "Contents": "",
            "ContentsFormat": "text",
            "Type": CommonServerPython.EntryType.ENTRY_INFO_FILE,
            "File": "pikachu.pdf",
            "FileID": file_result["FileID"],
        }
        # Retrieve the write calls to the mock file and assert the content
        assert handle.write.call_args[0][0] == b"Decoded Pikachu"
