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
        # Add the last response again, as we try to unshorten the final URL since we don't know that it's not shortened.
        mock_data.append(mock_data[-1])

        def redirect_side_effect() -> dict:
            for d in mock_data:
                yield d

        mocker.patch.object(BaseClient, "_http_request", side_effect=redirect_side_effect())

        result = unshorten_url(service="unshorten.me",
                               url=args["url"],
                               redirect_limit=args["redirect_limit"])

        assert result.outputs["RedirectCount"] <= args["redirect_limit"]
        assert result.outputs == expected_output


class TestBuiltInService:
    @staticmethod
    def get_response_mock(url: str, redirect_url: str | None = None, response_code: int | None = 200) -> Response:
        """
        Create a mock requests.Response object.

        Args:
            url (str): URL to set as the `url` attribute (should be the last URL in the redirect chain).
            redirect_url (str | None, optional): URL to redirect to. Defaults to None.
            response_code (int | None, optional): Response code to set as the `status_code` attribute.
              Not relevant if `redirect_url` is set (301 will be used). Defaults to None.

        Returns:
            Response: A requests.Response object to use as a mock.
        """
        response_mock = Response()
        response_mock.url = url

        if redirect_url is not None:
            response_mock.status_code = 301
            response_mock.headers["Location"] = redirect_url
            # response_mock.is_redirect = True

        else:
            response_mock.status_code = response_code
            # response_mock.is_redirect = False

        return response_mock

    @pytest.mark.parametrize("args, responses, expected_output",
                             [
                                 (
                                     {"url": "https://short.url/a", "redirect_limit": 6},
                                     [get_response_mock(url="https://short.url/a",
                                                        redirect_url="https://short.url/b"),
                                      get_response_mock(url="https://short.url/b",
                                                        redirect_url="https://xsoar.pan.dev/"),
                                      get_response_mock(url="https://xsoar.pan.dev/")],
                                     load_test_data("built-in", "nested_unshorten_expected_output"),
                                 ),
                                 (
                                     {"url": "https://short.url/a", "redirect_limit": 1},
                                     [get_response_mock(url="https://short.url/a",
                                                        redirect_url="https://short.url/b"),
                                      get_response_mock(url="https://short.url/b",
                                                        redirect_url="https://xsoar.pan.dev/"),
                                      get_response_mock(url="https://xsoar.pan.dev/")],
                                     load_test_data("built-in", "limited_unshorten_expected_output"),
                                 ),
                             ])
    def test_shortened_url(self, mocker, args: dict, responses: list[Response], expected_output: dict):
        """
        Given: Parameters for Built-In unshortening a URL using the 'requests' library.
        When: Calling the `unshorten_url` function.
        Then: Ensure the context output is returned as expected, and that redirect_limit is working as expected.
        """
        def redirect_side_effect() -> Response:
            for response in responses:
                yield response

        mocker.patch.object(BaseClient, "_http_request", side_effect=redirect_side_effect())

        assert unshorten_url(service="Built-In",
                             url=args["url"],
                             redirect_limit=args["redirect_limit"]).outputs == expected_output
