import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from abc import ABCMeta
from typing import NamedTuple, Type

from requests import Response


urllib3.disable_warnings()  # Disable insecure warnings

DEFAULT_SERVICE = "unshorten.me"
DEFAULT_REDIRECT_LIMIT = "0"


class URLUnshorteningData(NamedTuple):
    """
    A tuple containing data for unshortend URLs.

    Attributes:
        original_url (str): The original URL.
        resolved_url (str): The resolved URL.
        service_name (str): The name of the service used to resolve the URL.
        redirect_history (list): A list of URLs that were redirected to get to the resolved URL.
        raw_data (dict | list[dict] | None, optional): The raw data returned by the service. None if not available.
        encountered_error (bool, optional): Whether an error was encountered while resolving the URL. Defaults to False.
        api_usage (int | None, optional): The API usage count for the current IP. None if not relevant to the service.
        api_rate_limit (int | None, optional): The maximum number of API calls allowed by the service
          for a defined period of time. None if not relevant to the service.
    """
    original_url: str
    resolved_url: str
    service_name: str
    redirect_history: list[str]
    raw_data: dict | list[dict] | None = None
    encountered_error: bool = False
    api_usage: int | None = None
    api_rate_limit: int | None = None

    def to_context_dict(self) -> dict:
        """
        Converts the data to a dictionary that will be used as the context data.
        Adds recursion data only if relevant.

        Note:
            We subtract 1 from RedirectCount because the original URL is included in the recursion history.

        Returns:
            dict: A dictionary containing the data in context format.
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

        Returns:
            dict: A dictionary containing the data in human-readable format.
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
    """
    An abstract base class for URL unshorteners.

    Note:
        To add a new service, create a new class that inherits from this class, and implements the `resolve_url` method.
        The class attribute `service_name` must match the name used in the under `service` on the YAML file.
        Once created new service should be automatically detected and used.

    Attributes:
        base_url (str): The base URL of the service that will be used for sending requests.
        service_name (str): The name of the service.
        redirect_limit (int | None): The maximum number of redirects to follow. None if no limit.
    """
    base_url: str
    service_name: str
    service_rate_limit: int | None = None

    def __init__(self, redirect_limit: int | None = None, **kwargs):
        super().__init__(base_url=self.base_url, **kwargs)
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

    @staticmethod
    def find_matching_service(service_name: str) -> Type["URLUnshortingService"]:
        """
        Finds a matching service class by name.

        Args:
            service_name (str): The service name to find (has to match the service_name class attribute).

        Returns:
            Type[URLUnshortingService]: A subclass of URLUnshortingService that matches the service name.
        """
        for service_class in URLUnshortingService.__subclasses__():
            if service_class.service_name.casefold() == service_name.casefold():
                return service_class

        raise ValueError(f"No matching service was found for: \"{service_name}\".")

    @abstractmethod
    def resolve_url(self, url: str) -> URLUnshorteningData:  # pragma: no cover
        """
        Resolve a shortened URL.

        Args:
            url (str): The URL to resolve.

        Returns:
            URLUnshorteningData: A NamedTuple containing the data for the resolved URL.
        """
        pass


class LongurlInService(URLUnshortingService):
    """
    A class for unshortening URLs using longurl.in.

    Note:
        If the URL is invalid, the API returns {"status": "Failed", "message": "url is invalid"} with a 404 status_code.
    """
    base_url = "https://longurl.in/api/expand-url"
    service_name = "longurl.in"

    def resolve_url(self, url: str) -> URLUnshorteningData:
        encountered_error: bool = False
        original_url: str = url

        response: dict = self._http_request(
            method="POST",
            full_url=self.base_url,
            resp_type="json",
            data={"shortURL": url},
            error_handler=lambda _: None,  # Disable exception raising if API returns a 404
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
                error_handler=lambda _: None,  # Disable exception raising if API returns a 404
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
    service_name = "Built-In"

    def resolve_url(self, url: str) -> URLUnshorteningData:
        encountered_error = False
        original_url = url

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


def unshorten_url(service_name: str, url: str, redirect_limit: int, use_system_proxy: bool = False,
                  session_verify: bool = True) -> CommandResults:
    """
    Unshorten a shortened URL.

    Args:
        service_name (str): The service to use for unshortening.
        url (str): The URL to un-shorten.
        use_system_proxy (bool): Whether to use the system proxy.
        session_verify (bool): Whether to verify the SSL certificate of the request.
        redirect_limit (int): A maximum number of recursions to run. Use 0 for unlimited.
    """
    error_message = "There was an error while attempting to unshorten the final URL in the redirect chain.\n" \
                    "It is possible that the unshortening process was not fully completed.\n\n"

    service_class = URLUnshortingService.find_matching_service(service_name=service_name)
    service_instance = service_class(redirect_limit=redirect_limit,
                                     proxy=use_system_proxy,
                                     verify=session_verify)
    returned_data = service_instance.resolve_url(url=url)

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
    args = demisto.args()

    try:
        url: str = args["url"]
        service: str = args.get("service", DEFAULT_SERVICE)
        use_system_proxy = argToBoolean(args.get("use_system_proxy", "False"))
        redirect_limit = arg_to_number(args.get("redirect_limit", DEFAULT_REDIRECT_LIMIT))

        # `arg_to_number` returns `None` if int conversion was unsuccessful.
        if redirect_limit is None:
            raise ValueError("'redirect_limit' must be a natural number.")

        session_verify = not argToBoolean(args.get("insecure", "False"))

        result = unshorten_url(service_name=service,
                               url=url,
                               use_system_proxy=use_system_proxy,
                               redirect_limit=redirect_limit,
                               session_verify=session_verify)
        return_results(result)

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
