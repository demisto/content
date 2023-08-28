
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_CONTEXT_BRAND = "DeHashed"
BASE_URL = "https://api.dehashed.com/"
RESULTS_FROM = 1
RESULTS_TO = 50


class Client(BaseClient):
    def __init__(
        self,
        base_url,
        verify=True,
        proxy=False,
        ok_codes=None,
        headers=None,
        auth=None,
        email=None,
        api_key=None,
        email_dbot_score='SUSPICIOUS'
    ):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            ok_codes=ok_codes,
            headers=headers,
            auth=auth,
        )
        self.email = email
        self.api_key = api_key
        self.email_dbot_score = email_dbot_score

    def dehashed_search(self, asset_type: str | None, value: list[str], operation: str | None,
                        results_page_number: int | None = None) -> dict:
        """
        this function gets query parameters from demisto and perform a "GET" request to Dehashed api
        :param asset_type: email, ip_address, username, hashed_password, name, vin, address, phone,all_fields.
        :param value: value to search
        :param operation: choose a search type to perform.
        :param results_page_number: a page number to get. every page contains 5,000 entries.
        :return: a dictionary containing: a list of entries that match the query, number of total results exits for the
         given query, request status, how much time the request took, and balance.
        """

        if not value:
            raise DemistoException('This command must get "value" as argument')

        query_value = ""
        if len(value) > 1:
            if operation == "is":
                query_value = " ".join(f'"{value}"' for value in value)
            elif operation == "contains":
                query_value = " OR ".join(value)
                query_value = f"({query_value})"

            elif operation == "regex":
                query_value = " ".join(f"/{value}/" for value in value)
        else:
            if operation == "is":
                query_value = f'"{value[0]}"'
            elif operation == "contains":
                query_value = value[0]
            elif operation == 'regex':
                query_value = f"/{value[0]}/"

        query_string = f"{query_value}" if asset_type == "all_fields" else f"{asset_type}:{query_value}"

        if results_page_number:
            return self._http_request(
                "GET",
                "search",
                params={"query": query_string, "page": results_page_number},
                auth=(self.email, self.api_key),
                timeout=25,
            )
        else:
            return self._http_request(
                "GET",
                "search",
                params={"query": query_string},
                auth=(self.email, self.api_key),
                timeout=25
            )


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: DeHashed client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    result = client.dehashed_search(
        asset_type="vin", value=["test", "test1"], operation="is"
    )
    if isinstance(result, dict):
        return "ok"
    else:
        return f"Test failed because got unexpected response from api: {result}"


def validate_filter_parameters(results_from_value, results_to_value):
    if results_to_value <= 0:
        raise DemistoException(f'Argument "results_to" expected to be greater than zero, but given:'
                               f' {results_to_value}')
    elif results_from_value <= 0:
        raise DemistoException(f'Argument "results_from" expected to be greater than zero, but given:'
                               f' {results_from_value}')
    elif results_to_value > results_from_value:
        raise DemistoException('Argument "results_to" expected to be less than or equal to "results_from"')


def filter_results(
    entries: list, results_from: int | None, results_to: int | None
) -> tuple:
    """
    gets raw results returned from the api and limit the number of entries to return to demisto
    :param entries: search results of the performed query
    :param results_from: start range
    :param results_to: end range
    :return: filtered results
    """
    if not results_from:
        results_from = RESULTS_FROM
    if not results_to:
        results_to = RESULTS_TO
    if results_to > len(entries):
        results_to = len(entries)
    validate_filter_parameters(results_to, results_from)

    return entries[results_from - 1:results_to], results_from, results_to


def arg_to_int(arg_val: str | None, arg_name: str | None) -> int | None:
    """
    converts commands arguments to integers
    :param arg_name: argument name
    :param arg_val: value to convert to int
    :return: converted argument as int
    """
    if arg_val is None:
        return None
    if not isinstance(arg_val, str):
        return None
    try:
        result = int(arg_val)
        if result <= 0:
            raise DemistoException(f'"{arg_name}" expected to be greater than zero.')
        return result
    except ValueError:
        raise DemistoException(
            f'"{arg_name}" expected to be Integer. passed {arg_val} instead.'
        )


def create_dbot_score_dictionary(indicator_value, indicator_type, dbot_score, reliability):
    return {
        'Indicator': indicator_value,
        'Type': indicator_type,
        'Vendor': INTEGRATION_CONTEXT_BRAND,
        'Score': dbot_score,
        'Reliability': reliability
    }


def dehashed_search_command(client: Client, args: dict[str, str]) -> tuple:
    """
    this command returns data regarding a compromised assets given as arguments
    :param client: Demisto client
    :param args:
    - asset_type: email, ip_address, username, hashed_password, name, vin, address, phone,all_fields.
    - value: value to search
    - operation: choose a search type to perform.
    - results_page_number: a page number to get. every page contains 5,000 entries.
    - results_from: sets result's start range
    - results_to: sets result's end range
    :return: Demisto outputs
    """
    asset_type = args.get("asset_type")
    operation = args.get("operation")
    value = argToList(args.get("value"))
    results_page_number = arg_to_int(args.get("page"), "page")
    results_from = arg_to_int(args.get("results_from"), "results_from")
    results_to = arg_to_int(args.get("results_to"), "results_to")

    result = client.dehashed_search(asset_type, value, operation, results_page_number)
    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_data = result.get("entries")

    if not query_data:
        return "No matching results found", None, None
    else:
        filtered_results, results_from, results_to = filter_results(
            query_data, results_from, results_to
        )
        query_entries = createContext(
            filtered_results, keyTransform=underscoreToCamelCase
        )
        headers = [key.replace("_", " ") for key in [*filtered_results[0].keys()]]
        if not results_page_number:
            results_page_number = 1
        last_query = {
            "ResultsFrom": results_from,
            "ResultsTo": results_to,
            "DisplayedResults": len(filtered_results),
            "TotalResults": result.get("total"),
            "PageNumber": results_page_number
        }
        return (
            tableToMarkdown(
                f'DeHashed Search - got total results: {result.get("total")}, page number: {results_page_number}'
                f', page size is: {len(filtered_results)}. returning results from {results_from} to {results_to}.',
                filtered_results,
                headers=headers,
                headerTransform=pascalToSpace,
            ),
            {
                f"{INTEGRATION_CONTEXT_BRAND}.LastQuery(true)": last_query,
                f"{INTEGRATION_CONTEXT_BRAND}.Search(val.Id==obj.Id)": query_entries,

            },
            filtered_results,
        )


def email_command(client: Client, args: dict[str, str], reliability: str) -> tuple:
    """
    This command returns data regarding a compromised email address
    :param client: Demisto client
    :param args:
    - email: the email address that should be checked
    :param reliability: The reliability of the intelligence source.
    :return: Demisto outputs
    """
    email_address = argToList(args.get('email'))
    result = client.dehashed_search('email', email_address, 'contains')
    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_data = result.get("entries")
    if not query_data:
        context = {
            'DBotScore':
                {
                    'Indicator': email_address[0],
                    'Type': 'email',
                    'Vendor': INTEGRATION_CONTEXT_BRAND,
                    'Score': 0,
                    'Reliability': reliability
                }
        }
        return "No matching results found", context, None
    else:
        default_dbot_score_email = 2 if client.email_dbot_score == 'SUSPICIOUS' else 3
        query_entries = createContext(query_data, keyTransform=underscoreToCamelCase)
        sources = [entry.get('obtained_from') for entry in query_data if entry.get('obtained_from')]
        headers = [key.replace("_", " ") for key in [*query_data[0].keys()]]

        hr = tableToMarkdown(f'DeHashed Search - got total results: {result.get("total")}', query_data, headers=headers,
                             headerTransform=pascalToSpace)
        dbot_score = default_dbot_score_email if len(sources) > 0 else 0
        context = {
            f'{INTEGRATION_CONTEXT_BRAND}.Search(val.Id==obj.Id)': query_entries,
            'DBotScore': create_dbot_score_dictionary(email_address[0], 'email', dbot_score, reliability)
        }
        return hr, context, query_data


def main():  # pragma: no cover
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    demisto_params = demisto.params()
    email = demisto_params.get("credentials", {}).get('identifier', '')
    api_key = demisto_params.get("credentials", {}).get('password', '')
    base_url = BASE_URL
    verify_certificate = not demisto_params.get("insecure", False)
    proxy = demisto_params.get("proxy", False)
    email_dbot_score = demisto_params.get('email_dbot_score', 'SUSPICIOUS')
    reliability = demisto_params.get('integration_reliability', '')

    LOG(f"Command being called is {demisto.command()}")
    try:
        client = Client(
            base_url,
            verify=verify_certificate,
            email=email,
            api_key=api_key,
            proxy=proxy,
            headers={"accept": "application/json"},
            email_dbot_score=email_dbot_score
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == "dehashed-search":
            return_outputs(*dehashed_search_command(client, demisto.args()))
        elif demisto.command() == "email":
            return_outputs(*email_command(client, demisto.args(), reliability))
        else:
            return_error('Command not found.')
    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
