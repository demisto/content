import json
from pathlib import Path

import pytest
from requests import Response

from ResolveShortenedURL import *


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json", "r") as f:
        return json.load(f)


class TestUnshortenMeService:
    @pytest.mark.parametrize("args, mock_files_prefix, mock_files_count, expected_output",
                             [
                                 (  # General test
                                     {"url": "https://short.url/a", "redirect_limit": 6},
                                     "nested_unshorten",
                                     3,
                                     load_test_data("unshorten.me", "nested_unshorten_expected_output"),
                                 ),
                                 (  # Test a case where redirect is stopped because of `redirect_limit`
                                     {"url": "https://short.url/a", "redirect_limit": 1},
                                     "nested_unshorten",
                                     2,
                                     load_test_data("unshorten.me", "limited_unshorten_expected_output"),
                                 ),
                             ])
    def test_shortened_url(self, mocker, args: dict, mock_files_prefix: str,
                           mock_files_count: int, expected_output: dict):
        """
        Given: Parameters for unshortening a URL using unshorten.me.
        When: Calling the `unshorten_url` function.
        Then: Ensure the context output is returned as expected, and that redirect_limit is working as expected.
        """
        mock_data = [load_test_data("unshorten.me", mock_files_prefix + f"_{i}")
                     for i in range(mock_files_count)]

        def recursion_side_effect():
            for i in range(mock_files_count):
                yield mock_data[i]

        mocker.patch.object(BaseClient, "_http_request", side_effect=recursion_side_effect())

        result = unshorten_url(service="unshorten.me",
                               url=args["url"],
                               redirect_limit=args["redirect_limit"])

        assert result.outputs["RedirectCount"] <= args["redirect_limit"]
        assert result.outputs == expected_output


class TestSelfService:
    @staticmethod
    def get_response_mock(url: str, status_code: int, previous_response: Response | None = None) -> Response:
        """
        Create a mock requests.Response object.

        Args:
            url (str): URL to set as th `url` attribute (should be the last URL in the redirect chain).
            status_code (int): Status code to set as the `status_code` attribute.
            previous_response (Response | None, optional): Previous response in the redirect chain to use
                for the `history` attribute. Defaults to None.

        Returns:
            Response: A requests.Response object to use as a mock.
        """
        response_mock = Response()
        response_mock.url = url
        response_mock.status_code = status_code,

        response_mock.history = []

        if previous_response is not None:
            response_mock.history.append(previous_response)
            response_mock.history.extend(previous_response.history)

        return response_mock

    @pytest.mark.parametrize("args, mock_response_obj, expected_output",
                             [
                                 (
                                     {"url": "https://short.url/a", "redirect_limit": 6},
                                     get_response_mock(
                                         url='https://xsoar.pan.dev/',
                                         status_code=200,
                                         previous_response=get_response_mock(
                                             url='https://short.url/b',
                                             status_code=301,
                                             previous_response=get_response_mock(
                                                 url='https://short.url/a',
                                                 status_code=301))),
                                     load_test_data("self", "nested_unshorten_expected_output"),
                                 ),
                                 (
                                     {"url": "https://short.url/a", "redirect_limit": 1},
                                     get_response_mock(
                                         url='https://xsoar.pan.dev/',
                                         status_code=200,
                                         previous_response=get_response_mock(
                                             url='https://short.url/b',
                                             status_code=301)),
                                     load_test_data("self", "limited_unshorten_expected_output"),
                                 ),
                             ])
    def test_shortened_url(self, mocker, args: dict, mock_response_obj: Response, expected_output: dict):
        """
        Given: Parameters for self unshortening a URL using the 'requests' library.
        When: Calling the `unshorten_url` function.
        Then: Ensure the context output is returned as expected, and that redirect_limit is working as expected.
        """
        mocker.patch.object(BaseClient, "_http_request", return_value=mock_response_obj)

        assert unshorten_url(service="Self",
                             url=args["url"],
                             redirect_limit=args["redirect_limit"]).outputs == expected_output
