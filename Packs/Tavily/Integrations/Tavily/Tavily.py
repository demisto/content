from CommonServerPython import *  # noqa: F401

import requests
import warnings
import urllib3

warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TavilyExtractClient(BaseClient):

    def __init__(self, api_key, url="https://api.tavily.com/extract", proxy: bool = False, verify: bool = False):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        super().__init__(base_url=url, verify=verify, headers=headers, proxy=proxy)

    def extract(self, urls: list[str], extract_depth: str = "basic", include_images: bool = False) -> dict:

        payload = {
            "urls": urls,
            "extract_depth": extract_depth,
            "include_images": include_images
        }

        response = requests.post(self._base_url, headers=self._headers, json=payload, verify=self._verify)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Request failed: {response.status_code} - {response.text}")


def extarct_command(client: TavilyExtractClient, args: dict) -> CommandResults:
    """
    This function extracts the content from the given urls.
    """
    response = client.extract(argToList(args.get("urls")), extract_depth="advanced", include_images=False)
    final_results_content: list[dict] = []
    results = response.get("results", [])
    final_results_content.extend(
        {
            "URL": result.get("url"),
            "Content": result.get("raw_content", "No content found."),
        }
        for result in results
    )
    return CommandResults(outputs=final_results_content, readable_output="Extract content is finished", outputs_prefix="Tavily")


def main():
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
            return_results('ok')
        elif command == 'extract':
            return_results(extarct_command(client=client, args=args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")
    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
