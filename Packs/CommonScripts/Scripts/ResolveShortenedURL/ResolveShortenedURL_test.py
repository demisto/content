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
    with open(Path("test_data") / folder / f"{file_name}.json") as f:
        return json.load(f)


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

        else:
            response_mock.status_code = response_code

        return response_mock

    @pytest.mark.parametrize(
        "args, responses, expected_output",
        [
            (  # Generic test
                {"url": "https://short.url/a", "redirect_limit": 0},
                [
                    get_response_mock(url="https://short.url/a", redirect_url="https://short.url/b"),
                    get_response_mock(url="https://short.url/b", redirect_url="https://xsoar.pan.dev/"),
                    get_response_mock(url="https://xsoar.pan.dev/"),
                ],
                load_test_data("built-in", "nested_unshorten_expected_output"),
            ),
            (  # Test a case where redirect is stopped because of `redirect_limit`
                {"url": "https://short.url/a", "redirect_limit": 1},
                [
                    get_response_mock(url="https://short.url/a", redirect_url="https://short.url/b"),
                    get_response_mock(url="https://short.url/b", redirect_url="https://xsoar.pan.dev/"),
                    get_response_mock(url="https://xsoar.pan.dev/"),
                ],
                load_test_data("built-in", "limited_unshorten_expected_output"),
            ),
            (  # Test for URL without https:// prefix
                {"url": "short.url/a", "redirect_limit": 0},
                [
                    get_response_mock(url="short.url/a", redirect_url="https://short.url/b"),
                    get_response_mock(url="https://short.url/b", redirect_url="https://xsoar.pan.dev/"),
                    get_response_mock(url="https://xsoar.pan.dev/"),
                ],
                load_test_data("built-in", "no_https_unshorten_expected_output"),
            ),
        ],
    )
    def test_nested_shortened_url(self, mocker, args: dict, responses: list[Response], expected_output: dict):
        """
        Given: Parameters for unshortening a URL that redirects to another shortened URL using Python's requests lib.
        When: Calling the `unshorten_url` function.
        Then: Ensure the context output is returned as expected, and that redirect_limit is working as expected.
        """

        def redirect_side_effect() -> Response:
            yield from responses

        mocker.patch.object(BaseClient, "_http_request", side_effect=redirect_side_effect())

        result = unshorten_url(service_name="Built-In", url=args["url"], redirect_limit=args["redirect_limit"])

        assert result.outputs["RedirectCount"] <= args["redirect_limit"] or args["redirect_limit"] == 0
        assert result.outputs == expected_output

    @pytest.mark.parametrize(
        "args, response, expected_output",
        [
            (  # Test a case where the URL is invalid
                {"url": "https://invalid.url", "redirect_limit": 0},
                None,
                load_test_data("built-in", "invalid_url_expected_output"),
            ),
        ],
    )
    def test_single_shortened_url(self, mocker, args: dict, response: Response | None, expected_output: dict):
        """
        Given: Parameters for unshortening a shortened URL using Python's requests lib.
        When: Calling the `unshorten_url` function.
        Then: Ensure the context output is returned as expected, and that redirect_limit is working as expected.

        Note:
            Use `None` for raising an exception.
        """
        if response is None:
            mocker.patch.object(requests.sessions.Session, "request", side_effect=requests.exceptions.ConnectionError())

        else:
            mocker.patch.object(BaseClient, "_http_request", return_value=response)

        result = unshorten_url(service_name="Built-In", url=args["url"], redirect_limit=args["redirect_limit"])
        assert result.outputs == expected_output

    def test_exception_during_redirect(self, mocker):
        """
        Given: A URL that redirects successfully once, then throws an exception on the second redirect.
        When: Calling the `unshorten_url` function with redirect_limit=0 (unlimited).
        Then: Ensure that when an exception occurs during redirect and redirect limit hasn't been hit,
              encountered_error is set to True and the function breaks out of the redirect loop.
        """
        first_response = self.get_response_mock(
            url="https://short.url/redirect-exception", redirect_url="https://intermediate.url/step1"
        )

        # Mock the _http_request to return first response, then raise exception on second call
        def side_effect_with_exception(*args, **kwargs):
            if side_effect_with_exception.call_count == 0:
                side_effect_with_exception.call_count += 1
                return first_response
            else:
                raise requests.exceptions.ConnectionError("Connection failed during redirect")

        side_effect_with_exception.call_count = 0
        mocker.patch.object(BaseClient, "_http_request", side_effect=side_effect_with_exception)

        result = unshorten_url(
            service_name="Built-In",
            url="https://short.url/redirect-exception",
            redirect_limit=0,  # Unlimited redirects, so hit_redirect_limit should return False
        )

        expected_output = load_test_data("built-in", "redirect_exception_expected_output")

        assert result.outputs == expected_output
        assert result.outputs["EncounteredError"] is True
        assert result.outputs["RedirectCount"] == 1  # Should have one redirect before exception
        assert result.outputs["ResolvedURL"] == "https://intermediate.url/step1"  # Should stop at last successful URL


class TestURLUnshortingService:
    """Test the base URLUnshortingService class methods."""

    def test_hit_redirect_limit_unlimited(self):
        """
        Given: A BuiltInShortener instance with unlimited redirects (redirect_limit=0).
        When: Checking if the redirect limit has been hit with various redirect histories.
        Then: Ensure that hit_redirect_limit always returns False (unlimited redirects).
        """
        service = BuiltInShortener(redirect_limit=0)

        assert service.hit_redirect_limit([]) is False
        assert service.hit_redirect_limit(["url1"]) is False
        assert service.hit_redirect_limit(["url1", "url2", "url3"]) is False

    def test_hit_redirect_limit_with_limit(self):
        """
        Given: A BuiltInShortener instance with specific redirect limits.
        When: Checking if the redirect limit has been hit with different redirect histories.
        Then: Ensure that hit_redirect_limit returns True when the limit is reached or exceeded,
              and False otherwise.
        """

        service = BuiltInShortener(redirect_limit=2)
        assert service.hit_redirect_limit([]) is False  # 0 < 2
        assert service.hit_redirect_limit(["url1"]) is False  # 1 < 2
        assert service.hit_redirect_limit(["url1", "url2"]) is True  # 2 >= 2
        assert service.hit_redirect_limit(["url1", "url2", "url3"]) is True  # 3 >= 2

        service_limit_1 = BuiltInShortener(redirect_limit=1)
        assert service_limit_1.hit_redirect_limit([]) is False  # 0 < 1
        assert service_limit_1.hit_redirect_limit(["url1"]) is True  # 1 >= 1


class TestEdgeCases:
    """Test edge cases and additional scenarios."""

    def test_url_without_http_prefix(self, mocker):
        """
        Given: A URL without an http/https prefix.
        When: Calling the `unshorten_url` function with the URL missing the prefix.
        Then: Ensure the function adds 'https://' prefix and resolves the URL correctly without errors.
        """
        response_mock = TestBuiltInService.get_response_mock(url="https://example.com")
        mocker.patch.object(BaseClient, "_http_request", return_value=response_mock)

        result = unshorten_url(service_name="Built-In", url="example.com", redirect_limit=0)

        assert result.outputs["OriginalURL"] == "example.com"
        assert result.outputs["ResolvedURL"] == "https://example.com"
        assert result.outputs["EncounteredError"] is False

    def test_constructor_with_none_redirect_limit(self):
        """
        Given: A BuiltInShortener instance is created with `redirect_limit=None`.
        When: Initializing the service.
        Then: Ensure that the redirect_limit defaults to 0 and behaves like unlimited redirects.
        """
        service = BuiltInShortener(redirect_limit=None)
        assert service.redirect_limit == 0

        assert service.hit_redirect_limit(["url1", "url2"]) is False

    def test_find_matching_service_valid(self):
        """
        Given: A valid service name in different capitalizations.
        When: Calling `find_matching_service` with the service name.
        Then: Ensure that the correct service class (BuiltInShortener) is returned,
        regardless of the input's case sensitivity.
        """
        service_class = URLUnshortingService.find_matching_service("Built-In")
        assert service_class == BuiltInShortener

        service_class = URLUnshortingService.find_matching_service("built-in")
        assert service_class == BuiltInShortener

        service_class = URLUnshortingService.find_matching_service("BUILT-IN")
        assert service_class == BuiltInShortener

    def test_find_matching_service_invalid(self):
        """
        Given: An invalid or empty service name.
        When: Calling `find_matching_service` with that name.
        Then: Ensure a ValueError is raised with an appropriate error message.
        """
        with pytest.raises(ValueError, match='No matching service was found for: "InvalidService"'):
            URLUnshortingService.find_matching_service("InvalidService")

        with pytest.raises(ValueError, match='No matching service was found for: ""'):
            URLUnshortingService.find_matching_service("")

    def test_redirect_limit_enforcement_in_resolve_url(self, mocker):
        """
        Given: A sequence of mocked HTTP responses representing multiple redirects.
        When: Calling `unshorten_url` with a redirect limit of 2.
        Then: Ensure the resolution process stops after two redirects and returns
            the correct intermediate URL, along with accurate context data.
        """
        responses = [
            TestBuiltInService.get_response_mock(url="https://short.url/start", redirect_url="https://short.url/step1"),
            TestBuiltInService.get_response_mock(url="https://short.url/step1", redirect_url="https://short.url/step2"),
            TestBuiltInService.get_response_mock(url="https://short.url/step2", redirect_url="https://final.url"),
            TestBuiltInService.get_response_mock(url="https://final.url"),
        ]

        def side_effect(*args, **kwargs):
            return responses[side_effect.call_count]

        side_effect.call_count = 0

        def increment_side_effect(*args, **kwargs):
            result = side_effect(*args, **kwargs)
            side_effect.call_count += 1
            return result

        mocker.patch.object(BaseClient, "_http_request", side_effect=increment_side_effect)

        result = unshorten_url(service_name="Built-In", url="https://short.url/start", redirect_limit=2)

        assert result.outputs["RedirectCount"] == 2
        assert result.outputs["ResolvedURL"] == "https://short.url/step2"
        assert result.outputs["EncounteredError"] is False


class TestURLUnshorteningData:
    """
    Given: A URLUnshorteningData instance with basic values (no API usage or rate limits).
    When: Calling the `to_context_dict` method.
    Then: Ensure the returned dictionary includes correct context keys and values, including
          redirect count and error status.
    """

    def test_to_context_dict_basic(self):
        """Test to_context_dict with basic data (no API usage/rate limit)."""
        data = URLUnshorteningData(
            original_url="https://short.url",
            resolved_url="https://long.url",
            service_name="Built-In",
            redirect_history=["https://short.url", "https://long.url"],
            encountered_error=False,
        )

        result = data.to_context_dict()
        expected = {
            "OriginalURL": "https://short.url",
            "ResolvedURL": "https://long.url",
            "ServiceName": "Built-In",
            "RedirectCount": 1,  # len(redirect_history) - 1
            "RedirectHistory": ["https://short.url", "https://long.url"],
            "EncounteredError": False,
        }
        assert result == expected

    def test_to_context_dict_with_api_data(self):
        """
        Given: A URLUnshorteningData instance that includes API usage and rate limit data,
            along with a redirect history and an encountered error.
        When: Calling the `to_context_dict` method.
        Then: Ensure the context dictionary correctly reflects all provided fields,
            including APIUsageCount and APIRateLimit, and calculates RedirectCount properly.
        """
        data = URLUnshorteningData(
            original_url="https://short.url",
            resolved_url="https://long.url",
            service_name="SomeAPI",
            redirect_history=["https://short.url"],
            api_usage=5,
            api_rate_limit=100,
            encountered_error=True,
        )

        result = data.to_context_dict()
        expected = {
            "OriginalURL": "https://short.url",
            "ResolvedURL": "https://long.url",
            "ServiceName": "SomeAPI",
            "RedirectCount": 0,  # len(redirect_history) - 1
            "RedirectHistory": ["https://short.url"],
            "EncounteredError": True,
            "APIUsageCount": 5,
            "APIRateLimit": 100,
        }
        assert result == expected

    def test_to_hr_dict_basic(self):
        """
        Given: A URLUnshorteningData instance with basic data (no API usage or multiple redirects).
        When: Calling the `to_hr_dict` method.
        Then: Ensure the human-readable dictionary correctly omits redirect history and API usage
            when minimal data is present.
        """
        data = URLUnshorteningData(
            original_url="https://short.url",
            resolved_url="https://long.url",
            service_name="Built-In",
            redirect_history=["https://short.url"],  # Single URL, should be None in HR
            encountered_error=False,
        )

        result = data.to_hr_dict()
        expected = {
            "Original URL": "https://short.url",
            "Resolved URL": "https://long.url",
            "Service Used": "Built-In",
            "Redirect History": None,  # Single URL in history
            "API Usage Count": None,
        }
        assert result == expected

    def test_to_hr_dict_with_redirects_and_api(self):
        """
        Given: A URLUnshorteningData instance containing multiple redirects, API usage, and rate limit data.
        When: Calling the `to_hr_dict` method.
        Then: Ensure the returned human-readable dictionary includes the full redirect history and
            API usage in the correct "usage/limit" format.
        """
        redirect_history = ["https://short.url", "https://intermediate.url", "https://long.url"]
        data = URLUnshorteningData(
            original_url="https://short.url",
            resolved_url="https://long.url",
            service_name="SomeAPI",
            redirect_history=redirect_history,
            api_usage=10,
            api_rate_limit=50,
            encountered_error=False,
        )

        result = data.to_hr_dict()
        expected = {
            "Original URL": "https://short.url",
            "Resolved URL": "https://long.url",
            "Service Used": "SomeAPI",
            "Redirect History": redirect_history,
            "API Usage Count": "10/50",
        }
        assert result == expected

    def test_to_hr_dict_api_usage_only(self):
        """
        Given: A URLUnshorteningData instance with API usage provided but no rate limit.
        When: Calling the `to_hr_dict` method.
        Then: Ensure the returned human-readable dictionary includes the redirect history
            and displays only the API usage (without a rate limit).
        """
        data = URLUnshorteningData(
            original_url="https://short.url",
            resolved_url="https://long.url",
            service_name="SomeAPI",
            redirect_history=["https://short.url", "https://long.url"],
            api_usage=25,
            api_rate_limit=None,
            encountered_error=False,
        )

        result = data.to_hr_dict()
        expected = {
            "Original URL": "https://short.url",
            "Resolved URL": "https://long.url",
            "Service Used": "SomeAPI",
            "Redirect History": ["https://short.url", "https://long.url"],
            "API Usage Count": "25",
        }
        assert result == expected
