import urllib3
from abc import ABCMeta
from typing import NamedTuple

from requests import Response

import demistomock as demisto
from CommonServerPython import *

urllib3.disable_warnings()  # Disable insecure warnings


class URLUnshorteningData(NamedTuple):
    """A tuple containing data for unshortend URLs."""
    original_url: str
    """The original URL."""

    resolved_url: str
    """The resolved URL."""

    service_name: str
    """The name of the service used to unshorten the URL."""

    redirect_history: list[str]
    """A list of redirection history of the URL."""

    raw_data: dict | list[dict] | None = None
    """The raw data returned by the API / service. None if not available."""

    encountered_error: bool = False
    """Whether an error was encountered during the unshortening process"""

    # --- Service Specific Data ---

    api_usage: int | None = None
    """The API usage count for the current IP. None if not relevant to the service."""

    api_rate_limit: int | None = None
    """The maximum number of API calls allowed by the service for a defined period of time.
       None if not relevant to the service."""

    def to_context_dict(self) -> dict:
        """
        Converts the data to a dictionary that will be used as the context data.
        Adds recursion data only if relevant.

        Note: We subtract 1 from RedirectCount because the original URL is included in the recursion history.
        """
        data = {
            "OriginalURL": self.original_url,
            "ResolvedURL": self.resolved_url,
            "ServiceName": self.service_name,
            "RedirectCount": len(self.redirect_history) - 1,
            "RedirectHistory": self.redirect_history,
            "EncounteredError": self.encountered_error,
        }

        if self.api_usage is not None:
            data["APIUsageCount"] = self.api_usage

        if self.api_rate_limit is not None:
            data["APIRateLimit"] = self.api_rate_limit

        return data

    def to_hr_dict(self) -> dict:
        """
        Converts the data to a dictionary that will be used as the human-readable data.
        """
        api_usage_hr: str | None = None

        if self.api_usage is not None:
            api_usage_hr = f"{self.api_usage}"

            if self.api_rate_limit is not None:
                api_usage_hr += f"/{self.api_rate_limit}"

        return {
            "Original URL": self.original_url,
            "Resolved URL": self.resolved_url,
            "Service Used": self.service_name,
            "Redirect History": self.redirect_history if len(self.redirect_history) > 1 else None,
            "API Usage Count": api_usage_hr if api_usage_hr is not None else None,
        }


class URLUnshortingService(BaseClient, metaclass=ABCMeta):
    """An abstract base class for URL unshorteners."""
    @property
    @abstractmethod
    def base_url(self) -> str:  # pragma: no cover
        pass

    @property
    @abstractmethod
    def service_name(self) -> str:  # pragma: no cover
        pass

    service_rate_limit: int | None = None

    def __init__(self, redirect_limit: int | None = None, *args, **kwargs):
        super().__init__(base_url=self.base_url, *args, **kwargs)
        self.redirect_limit = redirect_limit if redirect_limit is not None else 0

    def hit_redirect_limit(self, redirect_history: list) -> bool:
        """
        Checks whether the redirect limit has been reached.

        Args:
            redirect_history (list): The redirect history of the URL.

        Returns:
            bool: True if the redirect limit has been reached, False otherwise.
        """
        if self.redirect_limit == 0:
            return False

        return len(redirect_history) >= self.redirect_limit

    @abstractmethod
    def resolve_url(self, url: str) -> URLUnshorteningData:
        """
        Resolve a shortened URL.

        Args:
            url (str): The URL to resolve.
        """
        pass


# --- Abstract stuff end here ---

class LongurlInService(URLUnshortingService):
    """A class for unshortening URLs using longurl.in."""
    base_url = "https://longurl.in/api/expand-url"
    service_name = "longurl.in"

    # Notes:
    # - If the URL is invalid, the API returns {"status": "Failed", "message": "url is invalid"} with a 404 status_code.

    def resolve_url(self, url: str) -> URLUnshorteningData:
        encountered_error: bool = False
        original_url: str = url

        response: dict = self._http_request(
            method="POST",
            full_url=self.base_url,
            resp_type="json",
            data={"shortURL": url},
            error_handler=lambda _: None,  # Disable exception raising if API returns a 404  # type: ignore
        )

        raw_data: list[dict] = [response]
        redirect_history: list[str] = []

        # Assure API's `status` key exists and equals "OK", and that `data` key exists with at least one element.
        while (response.get("status") == "OK") and len(response.get("data", [])) > 0 and \
                response["data"][0] is not None and (not self.hit_redirect_limit(redirect_history)):
            url = response["data"][0]

            response = self._http_request(
                method="POST",
                full_url=self.base_url,
                resp_type="json",
                data={"shortURL": url},
                error_handler=lambda _: None,  # Disable exception raising for  # type: ignore
            )

            raw_data.append(response)
            redirect_history.append(url)

        # Stopped because of an error, without hitting `redirect_limit` (which would mean we don't care about the error)
        if response.get("status") != "OK" and (not self.hit_redirect_limit(redirect_history)):
            encountered_error = True

        return URLUnshorteningData(
            original_url=original_url,
            resolved_url=url,
            service_name=self.service_name,
            redirect_history=[original_url] + redirect_history,
            raw_data=raw_data,
            encountered_error=encountered_error,
        )


class UnshortenMeSservice(URLUnshortingService):
    """A class for unshortening URLs using unshorten.me."""
    base_url = "https://unshorten.me/json/"
    service_name = "unshorten.me"
    service_rate_limit = 10

    def resolve_url(self, url: str) -> URLUnshorteningData:
        encountered_error: bool = False
        original_url: str = url

        response: dict = self._http_request(
            method="GET",
            url_suffix=url,
            resp_type="json",
        )

        usage_count = response.get("usage_count", 0)

        raw_data: list[dict] = [response]
        redirect_history: list[str] = []
        previous_resolved_url: str | None = None

        while (previous_resolved_url != url) and response.get("success") and \
                (not self.hit_redirect_limit(redirect_history)):
            previous_resolved_url = url
            url = response.get("resolved_url", "")

            response = self._http_request(
                method="GET",
                url_suffix=url,
                resp_type="json",
            )

            raw_data.append(response)
            redirect_history.append(url)

            if response.get("usage_count"):
                usage_count = response["usage_count"]

        # Stopped because of an error, without hitting `redirect_limit` (which would mean we don't care about the error)
        if (not response.get("success")) and (not self.hit_redirect_limit(redirect_history)):
            encountered_error = True

        # If the last URL in the redirect history is the same as the resolved URL,
        # or if the resolved URL is the same as the original URL, remove it from `redirect_history`.
        if (len(redirect_history) >= 2 and redirect_history[-1] == redirect_history[-2]) or \
                (len(redirect_history) == 1 and redirect_history[0] == original_url):
            redirect_history.pop()

        return URLUnshorteningData(
            original_url=original_url,
            resolved_url=url,
            service_name=self.service_name,
            redirect_history=[original_url] + redirect_history,
            raw_data=raw_data,
            encountered_error=encountered_error,
            api_usage=usage_count,
            api_rate_limit=self.service_rate_limit,
        )


class BuiltInShortener(URLUnshortingService):
    """A class for unshortening URLs using Python requests."""
    base_url = ""
    service_name = "Built-in"

    def resolve_url(self, url: str) -> URLUnshorteningData:
        encountered_error: bool = False
        original_url: str = url

        try:
            response: Response = self._http_request(
                method="GET",
                full_url=url,
                resp_type="response",
                allow_redirects=False,
            )

        except Exception:
            encountered_error = True

        redirect_history: list[str] = []

        while not encountered_error and \
                (response.is_redirect and (not self.hit_redirect_limit(redirect_history))):
            url = response.headers["location"]
            redirect_history.append(url)

            try:
                response = self._http_request(
                    method="GET",
                    full_url=url,
                    resp_type="response",
                    allow_redirects=False,
                )

            except Exception:
                if not self.hit_redirect_limit(redirect_history):
                    encountered_error = True
                break

        return URLUnshorteningData(
            original_url=original_url,
            resolved_url=url,
            service_name=self.service_name,
            redirect_history=[original_url] + redirect_history,
            encountered_error=encountered_error,
        )


def unshorten_url(service: str, url: str, redirect_limit: int, session_verify: bool = True) -> CommandResults:
    """
    Unshorten a shortened URL.

    Args:
        service (str): The service to use for unshortening.
        url (str): The URL to un-shorten.
        session_verify (bool): Whether to verify the SSL certificate of the request.
        redirect_limit (int): A maximum number of recursions to run. Use 0 for unlimited.
    """
    error_message: str = "There was an error while attempting to unshorten the final URL in the redirect chain.\n" \
                         "It is possible that the unshortening process was not fully completed.\n\n"

    client: URLUnshortingService

    if service.casefold() == LongurlInService.service_name.casefold():
        client = LongurlInService(redirect_limit=redirect_limit, verify=session_verify)
    elif service.casefold() == UnshortenMeSservice.service_name.casefold():
        client = UnshortenMeSservice(redirect_limit=redirect_limit, verify=session_verify)
    elif service.casefold() == BuiltInShortener.service_name.casefold():
        client = BuiltInShortener(redirect_limit=redirect_limit, verify=session_verify)
    else:
        raise ValueError(f"Unknown service: {service}")

    returned_data = client.resolve_url(url=url)

    readable_output = ""

    if returned_data.encountered_error:
        readable_output += error_message

    readable_output += tableToMarkdown(name="URL Unshortening Results",
                                       t=returned_data.to_hr_dict(),
                                       headers=list(returned_data.to_hr_dict().keys()),
                                       removeNull=True)

    return CommandResults(
        outputs_prefix="ResolveShortenedURL",
        outputs_key_field="OriginalURL",
        outputs=returned_data.to_context_dict(),
        readable_output=readable_output,
        indicator=Common.URL(url=returned_data.resolved_url,
                             dbot_score=Common.DBotScore(
                                 indicator=returned_data.resolved_url,
                                 indicator_type=DBotScoreType.URL,
                                 integration_name="ResolveShortenedURL",
                                 score=Common.DBotScore.NONE,
                             )),
        raw_response=returned_data.raw_data,
    )


def main():  # pragma: no cover
    default_service = "unshorten.me"
    default_redirect_limit: int = 0  # Default value to use if `redirect_limit` is None

    args = demisto.args()

    try:
        url: str = args["url"]
        service: str = args.get("service", default_service)
        redirect_limit = arg_to_number(args.get("redirect_limit", str(default_redirect_limit)))

        # `arg_to_number` returns `None` if int conversion was unsuccessful.
        if redirect_limit is None:
            raise ValueError("'redirect_limit' must be a natural number.")

        session_verify = not argToBoolean(demisto.args().get("insecure", "False"))

        result = unshorten_url(service=service, url=url, redirect_limit=redirect_limit, session_verify=session_verify)
        return_results(result)

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
