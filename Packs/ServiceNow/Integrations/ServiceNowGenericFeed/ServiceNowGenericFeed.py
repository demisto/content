import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

""" CONSTANTS """
OAUTH_URL = "/oauth_token.do"
API_VERSION = "/api/now/cmdb/instance/"
ROOT_URL = "https://company.service-now.com"


class Client:
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(
        self,
        credentials: dict,
        use_oauth: bool = False,
        client_id: str = "",
        client_secret: str = "",
        url: str = "",
        verify: bool = False,
        proxy: bool = False,
        jwt_params: dict = None,
    ):
        """
        Args:
            - credentials: the username and password given by the user.
            - client_id: the client id of the application of the user.
            - client_secret - the client secret of the application of the user.
            - url: the instance url of the user, i.e: https://<instance>.service-now.com.
                   NOTE - url should be given without an API specific suffix as it is also used for the OAuth process.
            - insecure: Whether the request should verify the SSL certificate.
            - proxy: Whether to run the integration using the system proxy.
            - headers: The request headers, for example: {'Accept`: `application/json`}. Can be None.
            - use_oauth: a flag indicating whether the user wants to use OAuth 2.0 or basic authorization.
        """
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.use_oauth = use_oauth
        self.use_jwt = bool(jwt_params)
        self.snow_client: ServiceNowClient = ServiceNowClient(
            credentials=credentials,
            use_oauth=use_oauth,
            client_id=client_id,
            client_secret=client_secret,
            url=url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            jwt_params=jwt_params,
        )

    def records_list(self, method="GET", url_suffix=None, params=None):
        return self.snow_client.http_request(method=method, url_suffix=url_suffix, params=params)


"""COMMAND FUNCTIONS"""


def test_module(client: Client, args: dict, indicator: list) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: ServiceNow Genric Feed client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    # Notify the user that test button can't be used when using OAuth 2.0:

    if client.use_oauth and not client.use_jwt:
        return_error(
            "Test button cannot be used when using OAuth 2.0. Please use the !servicenow-cmdb-oauth-login "
            "command followed by the !servicenow-cmdb-oauth-test command to test the instance."
        )

    try:
        add_indicators_to_TIM(indicator)
    except Exception as e:
        raise e
    return "ok"


def records_list_command(client: Client, args: dict, params: dict) -> tuple:
    """
    Function to list the records
    """
    class_name = args.get("class")
    outputs = {"Class": class_name}
    response = client.records_list(method="GET", url_suffix=params.get("query_url"), params=params)
    result = response.get("result", {})
    if result:
        outputs["Records"] = result
        human_readable = tableToMarkdown(f"Found {len(result)} records for class {class_name}:", t=result)
    else:
        human_readable = f"Found no records for class {class_name}."
    #    context["ServiceNowGenericFeed(val.ID===obj.ID)"] = outputs

    return human_readable, response


def add_indicators_to_TIM(indicators: list):
    """
    Function to add indicators to TIM
    """

    if indicators:
        for b in batch(indicators, batch_size=2000):
            demisto.createIndicators(b)
    else:
        return "Indicators do not exist"
    return "success"


def create_indicator_object(indicator_list: list, feedtags: list, indicator_field: str) -> list:
    # create a for loop  which will iterate through the indicators input in list and output a list of dict
    indicator_objs = []
    for ind in indicator_list:
        indicator_obj = {
            "value": ind[indicator_field],
            "type": "IP",
            "fields": {"tags": feedtags},
            "rawJSON": ind,
        }

        indicator_objs.append(indicator_obj)

    return indicator_objs


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    url = params.get("url")
    if url is None:
        url = "https://northdakota.service-now.com/"
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    client_id = client_secret = ""
    credentials = params.get("credentials", {})
    use_oauth = params.get("use_oauth", False)
    use_jwt = params.get("use_jwt", False)
    feedtags = argToList(params.get("feedTags"))
    server_url = params.get("query_url")
    indicator_field = params.get("indicator_field")

    if server_url is None:
        return_error("Query URL not provided")
    jwt_params = {}

    # use jwt only with OAuth
    if use_jwt and use_oauth:
        raise ValueError("Please choose only one authentication method (OAuth or JWT).")

    elif use_jwt:
        use_oauth = True

    if use_oauth:
        client_id = credentials.get("identifier")
        client_secret = credentials.get("password")

    if use_jwt:
        if not params.get("private_key") or not params.get("kid") or not params.get("sub"):
            raise Exception("When using JWT, fill private key, kid and sub fields")
        jwt_params = {
            "private_key": params.get("private_key", {}).get("password"),
            "kid": params.get("kid"),
            "sub": params.get("sub"),
            "iss": params.get("iss", client_id),
            "aud": client_id,
        }

    client = Client(
        credentials=credentials,
        use_oauth=use_oauth,
        client_id=client_id,
        client_secret=client_secret,
        url=url,
        verify=verify,
        proxy=proxy,
        jwt_params=jwt_params,
    )

    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        if demisto.command() == "test-module":
            indicator = [{"manufacturer.name": "some network", "ip_address": "some ip"}]

            # This is the call made when pressing the integration Test button.
            obj = create_indicator_object(indicator, feedtags, indicator_field="ip_address")
            return_results(test_module(client, args, obj))

        elif demisto.command() == "fetch-indicators":
            # This is the call made when pressing the integration Test button.

            human_readable, response = records_list_command(client, args, params)
            if response.get("result", {}):
                indicators = response.get("result", {})
                objs = create_indicator_object(indicators, feedtags, indicator_field)
                add_indicators_to_TIM(objs)
            else:
                return_error("No indicators returned from ServiceNow")

        else:
            return_error("Command not found.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


from ServiceNowApiModule import *  # noqa: E402

""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
