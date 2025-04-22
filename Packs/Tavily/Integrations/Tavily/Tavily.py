from CommonServerPython import *  # noqa: F401

import warnings
import urllib3

warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TavilyExtractClient(BaseClient):

    def __init__(self, api_key, url="https://api.tavily.com", proxy: bool = False, verify: bool = False):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        super().__init__(base_url=url, verify=verify, headers=headers, proxy=proxy)

    def extract(self, url: str, extract_depth: str = "basic", include_images: bool = False) -> dict:

        payload = {
            "urls": [url],
            "extract_depth": extract_depth,
            "include_images": include_images
        }

        response = self._http_request("POST", url_suffix="extract", json_data=payload, headers=self._headers,
                                      resp_type='response')

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Request failed: {response.status_code} - {response.text}")


def extarct_command(client: TavilyExtractClient, args: dict) -> CommandResults:
    """
    This function extracts the content from the given url.
    """
    response = client.extract(args["url"], extract_depth="basic", include_images=False)
    results = response.get("results", [])
    if len(results) == 1:
        output = {
            "URL": results[0].get("url"),
            "Content": results[0].get("raw_content", "No content found."),
        }
        return CommandResults(outputs=output, readable_output="Successfully extract the content from {url}",
                              outputs_prefix="Tavily", outputs_key_field="URL")

    raise DemistoException(f"There are no results for the given url {args.get('url')}")


def test_module(client: TavilyExtractClient) -> str:
    """
    Sanity test with Google
    """
    client.extract("google.com", extract_depth="basic", include_images=False)
    return 'ok'


def main():  # pragma: no cover
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    api_key = params.get("api_key")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = TavilyExtractClient(api_key, url=url, verify=verify_certificate, proxy=proxy)
        demisto.debug(f"{client}")
        if command == "test-module":
            return_results(test_module(client=client))
        elif command == 'tavily-extract':
            return_results(extarct_command(client=client, args=args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
