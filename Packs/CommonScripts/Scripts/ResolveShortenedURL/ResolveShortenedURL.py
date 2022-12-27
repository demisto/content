from typing import NamedTuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
from requests import Response

from abc import ABCMeta, abstractmethod

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


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

    usage_count: int | None = None
    """The number of times the URL was unshortened. None if the service does not provide this information."""

    raw_data: dict | list[dict] | None = None
    """The raw data returned by the API / service. None if not available."""

    def to_context_dict(self) -> dict:
        """
        Converts the data to a dictionary that will be used as the context data.
        Adds recursion data only if relevant.

        Note: We subtract 1 from RedirectCount because the original URL is included in the recursion history.
        """
        return {
            "OriginalURL": self.original_url,
            "ResolvedURL": self.resolved_url,
            "ServiceName": self.service_name,
            "UsageCount": self.usage_count,
            "RedirectCount": len(self.redirect_history) - 1 if len(self.redirect_history) > 1 else None,
            "RedirectHistory": self.redirect_history if len(self.redirect_history) > 1 else None,
        }

    def to_hr_dict(self) -> dict:
        """
        Converts the data to a dictionary that will be used as the human-readable data.
        """
        return {
            "Original URL": self.original_url,
            "Resolved URL": self.resolved_url,
            "Service Used": self.service_name,
            "Usage Count": self.usage_count,
            "Redirect History": self.redirect_history if len(self.redirect_history) > 1 else None,
        }


class URLUnshortingService(BaseClient, metaclass=ABCMeta):  # pragma: no cover
    """An abstract base class for URL unshorteners."""
    @property
    @abstractmethod
    def base_url(self) -> str:
        pass

    @property
    @abstractmethod
    def service_name(self) -> str:
        pass

    def __init__(self, redirect_limit: int | None = None, *args, **kwargs):
        super().__init__(base_url=self.base_url)
        self.redirect_limit = redirect_limit if redirect_limit is not None else 0

    @abstractmethod
    def resolve_url(self, url: str) -> URLUnshorteningData:
        """
        Resolve a shortened URL.

        Args:
            url (str): The URL to resolve.
        """
        pass


# --- Abstract stuff end here ---

class UnshortenMeSservice(URLUnshortingService):
    """A class for unshortening URLs using unshorten.me."""
    base_url = 'https://unshorten.me/json/'
    service_name = "unshorten.me"

    def resolve_url(self, url: str) -> URLUnshorteningData:
        response = self._http_request(
            method='GET',
            url_suffix=url,
            resp_type="json",
        )

        usage_count = response.get('usage_count', 0)

        raw_data = [response]
        previous_resolved_url = url
        resolved_url = response.get('resolved_url')
        redirect_history = [url, resolved_url]

        # If redirect_limit is 0, it should be unlimited.
        # We add 1 to `redirect_limit` because the original URL is part of `redirect_history`.
        while (previous_resolved_url != resolved_url) and \
                (self.redirect_limit == 0 or len(redirect_history) < self.redirect_limit + 1):
            response = self._http_request(
                method='GET',
                url_suffix=resolved_url,
                resp_type="json",
            )

            raw_data.append(response)
            previous_resolved_url = resolved_url
            resolved_url = response.get('resolved_url')
            usage_count += response.get('usage_count', 0)
            redirect_history.append(resolved_url)

        if len(redirect_history) >= 2 and redirect_history[-1] == redirect_history[-2]:
            redirect_history.pop()

        return URLUnshorteningData(
            original_url=url,
            resolved_url=resolved_url,
            service_name=self.service_name,
            usage_count=usage_count,
            redirect_history=redirect_history,
            raw_data=raw_data,
        )


class SelfShortener(URLUnshortingService):
    """A class for unshortening URLs using Python requests."""
    base_url = ''
    service_name = "Self Unshortener"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.redirect_limit >= 2:
            self._session.max_redirects = self.redirect_limit - 1

    def resolve_url(self, url: str) -> URLUnshorteningData:
        request_kwargs: dict[str, Any] = {
            "method": "GET",
            "full_url": url,
            "resp_type": "response",
        }

        if self.redirect_limit == 1:
            request_kwargs["allow_redirects"] = False

        response: Response = self._http_request(**request_kwargs)

        return URLUnshorteningData(
            original_url=url,
            resolved_url=response.url,
            service_name=self.service_name,
            redirect_history=[r.url for r in response.history + [response]],
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
    client: URLUnshortingService

    match service.lower():
        case "unshorten.me":
            client = UnshortenMeSservice(redirect_limit=redirect_limit,
                                         verify=session_verify)

        case "self":
            client = SelfShortener(redirect_limit=redirect_limit,
                                   verify=session_verify)

        case _:
            raise ValueError(f"Unknown service: {service}")

    returned_data = client.resolve_url(url=url)

    return CommandResults(
        outputs_prefix="ResolveShortenedURL",
        outputs_key_field="OriginalURL",
        outputs=returned_data.to_context_dict(),
        readable_output=tableToMarkdown(name="URL Unshortening Results",
                                        t=returned_data.to_hr_dict(),
                                        headers=list(returned_data.to_hr_dict().keys()),
                                        removeNull=True),
        indicator=Common.URL(url=returned_data.resolved_url, dbot_score=0),
        raw_response=returned_data.raw_data,
    )


def main():  # pragma: no cover
    default_redirect_limit: int = 10  # Default value to use if `redirect_limit` is None
    args = demisto.args()

    try:
        url: str = args['url']
        service: str = args['service']

        # If `redirect_limit` is 0, it means unlimited recursions. If it's 1, it means no recursions.
        redirect_limit = arg_to_number(args.get('redirect_limit', str(default_redirect_limit)))

        # `arg_to_number` returns `None` if int conversion was unsuccessful.
        if redirect_limit is None:
            raise ValueError("'redirect_limit' must be a number.")

        session_verify = not argToBoolean(demisto.args().get('insecure', 'False'))

        result = unshorten_url(service=service, url=url, redirect_limit=redirect_limit, session_verify=session_verify)
        return_results(result)

    except Exception as e:
        return_error(f'Provided URL could not be un-shortened.\nError: {str(e)}')


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
