"""XM Cyber CEM Integration for Cortex XSOAR."""

import operator
from copy import deepcopy
from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

TOTAL_RETRIES = 4
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201, 401, 419)
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S.000Z"
DEFAULT_ENTITY_VALUE: str = "XSOAR_TEST"
DASHBOARD_CACHE_DURATION = 3600  # 1 hour in seconds

ENDPOINTS = {
    "AUTH_ENDPOINT": "/api/auth",
    "REFRESH_TOKEN_ENDPOINT": "/api/refresh-token",
    "GET_ENTITIES_ENDPOINT": "/api/secopsPublisher/entities",
    "PUSH_BREACH_POINT_ENDPOINT": "/api/entityInventory/applyImportedLabelsOnEntities",
    "GET_SECURITY_SCORE_ENDPOINT": "/api/systemReport/riskScoreV2",
    "GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT": "/api/v2/reports/data/scenariosChokePointsReport/chokePointsEntities",
    "GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT": '/api/v2/reports/data/scenariosCriticalAssetsReport/entities?filter={"isAsset":true}',  # noqa: E501
    "GET_COMPROMISING_EXPOSURES_ENDPOINT": "/api/v2/reports/data/defaultReport/attackTechniques/techniques",
}

REQUEST_PARAMS = {
    "SECURITY_SCORE": {"timeId": "timeAgo_days_30", "resolution": "1"},
    "CHOKE_POINTS": {"entitiesCategory": "all", "suppressed": "false", "pageSize": "3", "sort": "-chokePointScore"},
    "CRITICAL_ASSETS": {"pageSize": "3", "sort": "-riskScore", "entitiesCategory": "all"},
    "COMPROMISING_EXPOSURES": {"pageSize": "3", "sort": "-criticalAssets"},
}

ERRORS = {
    "GENERAL_AUTH_ERROR": (
        "Status code: {}. Unauthorized request: 'Verify that you have a valid API Key and access to the server from your host'."
    ),
    "INVALID_OBJECT": "Failed to parse {} object from response: {}",
    "REQUIRED_ARGUMENT": "Please provide a valid value for the '{}'. It is required field.",
    "INVALID_COMMAND_ARG_VALUE": "Invalid '{}' value provided. Please ensure it is one of the values from the "
    "following options: {}.",
    "EQUALITY_INCORRECT_OPERATOR": "For '{}' parameter, operator must be 'Equals' or 'Not equal to'.",
    "CONTAINS_INCORRECT_PARAMETER": "For '{}' parameter, operator must be 'Contains' or 'Not Contains'.",
    "CONTAINS_INCORRECT_OPERATOR": "For '{}' parameter, operator cannot be 'Contains' or 'Not Contains'.",
    "INCORRECT_VALUE_TYPE": "For boolean and string values, operator must be 'Equals' or 'Not equal to'.",
    "MISSING_ENTITY_ID": "Entity '{}' does not have 'id' field. Skipping...",
    "INVALID_SCORE_VALUE": "Invalid '{}' value provided. Must be a valid number between 0 and 1.",
}

OUTPUT_PREFIXES = {
    "Entity": "XMCyber.Entity",
    "PushBreachPoint": "XMCyber.BreachPoint",
    "RemoveBreachPoint": "XMCyber.RemoveBreachPoint",
    "CalculateRiskScore": "XMCyber.CalculateRiskScore",
    "Dashboard": "XMCyber.Dashboard",
}

DEFAULT_ATTRIBUTE_NAME = "XSOAR_BP"
DEFAULT_OPERATOR = "Equals"
DEFAULT_PARAMETER = "All"
DEFAULT_VALUE = "True"

STRINGIFIED_LIST_PARAMETERS = ["labels"]
DATE_PARAMETERS = ["last login date", "last password set date"]
EQUALITY_PARAMETERS = ["entity id", "domain name"]

LEVELS_TO_SCORE = {
    "unknown": 0,
    "informative": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

PARAMETER_FIELD_MAPPING = {
    "entity id": "id",
    "affected unique entities": "affectedUniqueEntities",
    "choke point score": "chokePointScore",
    "compromise risk score": "riskScore",
    "labels": "Labels",
    "domain name": "domainName",
    "is enabled": "isEnabled",
    "last login date": "lastLogon",
    "last password set date": "pwdLastSet",
}
POSSIBLE_PARAMETERS = {
    "all": "All",
    "entity id": "Entity ID",
    "affected unique entities": "Affected Unique Entities",
    "compromise risk score": "Compromise Risk Score",
    "choke point score": "Choke Point Score",
    "labels": "Labels",
    "domain name": "Domain Name",
    "is enabled": "Is Enabled",
    "last login date": "Last Login Date",
    "last password set date": "Last Password Set Date",
}

EQUALITY_OPERATORS = ["equals", "not equal to"]
CONTAINS_OPERATORS = ["contains", "not contains"]
POSSIBLE_OPERATORS_VALUES = [
    "Less than",
    "Greater than",
    "Less than equal to",
    "Greater than equal to",
    "Equals",
    "Not equal to",
    "Contains",
    "Not contains",
]
POSSIBLE_OPERATORS = {
    "less than": operator.lt,
    "greater than": operator.gt,
    "less than equal to": operator.le,
    "greater than equal to": operator.ge,
    "equals": operator.eq,
    "not equal to": operator.ne,
    "contains": operator.contains,
    "not contains": operator.contains,
}

PACK_VERSION = get_pack_version() or "2.0.0"
CONNECTOR_NAME_VERSION = f"XSOAR-XMCyberCEM-v{PACK_VERSION}"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the XM Cyber API.

    This Client implements API calls to XM Cyber and handles authentication.
    It inherits from BaseClient to leverage the built-in _http_request functionality.
    """

    def __init__(self, server_url: str, api_key: str, verify: bool, proxy: bool):
        """
        Initializes the class instance.

        :param server_url: The URL of the server.
        :type server_url: str
        :param api_key: The API key for authentication.
        :type api_key: str
        :param verify: Indicates whether to verify the server's SSL certificate.
        :type verify: bool
        :param proxy: Indicates whether to use a proxy for the requests.
        :type proxy: bool
        """
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self.api_key = api_key

        # Fetch cached integration context.
        integration_context = get_integration_context()
        self._access_token = integration_context.get("access_token") or self._generate_token()

    def http_request(
        self,
        method: str,
        url_suffix: str = "",
        params: Union[dict[str, Any], list[tuple[str, Any]]] = None,
        data: dict[str, Any] = None,
        json_data: dict[str, Any] = None,
        response_type: str = "response",
        internal_retries: int = 3,
        **kwargs,
    ) -> Any | None:
        """
        Makes an HTTP request to the server.

        :param method: The HTTP method (e.g., GET, POST, PUT, DELETE).
        :type method: str
        :param url_suffix: The URL suffix to be appended to the base URL. Defaults to an empty string.
        :type url_suffix: str
        :param params: Query parameters to be appended to the URL. Defaults to None.
        :type params: Union[dict[str, Any], list[tuple[str, Any]]]
        :param data: Data to be sent in the request body. Defaults to None.
        :type data: dict[str, Any]
        :param json_data: JSON data to be sent in the request body. Defaults to None.
        :type json_data: dict
        :param response_type: The expected response type. Defaults to None.
        :type response_type: str
        :param internal_retries: Number of retries to make in case of failure. Defaults to 3.
        :type internal_retries: int
        :param kwargs: Additional keyword arguments.

        :return: The response object or None.
        :rtype: Any | None
        """
        # Set the headers for the request, including Authorization.
        headers = {"Authorization": f"Bearer {self._access_token}", "X-XMCYBER-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION}
        demisto.debug(f"Making API request at {method} {url_suffix} with params: {params} and body: {data or json_data}")
        # Make the HTTP request using the _http_request method, passing the necessary parameters.
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            data=data,
            json_data=json_data,
            params=params,
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            ok_codes=OK_CODES,
            backoff_factor=BACKOFF_FACTOR,
            resp_type="response",
            raise_on_status=True,
            **kwargs,
        )
        # If the response status code indicates an authentication issue (e.g., 401,419),
        # generate a new access token using the refresh token and retry the request.
        if res.status_code in (401, 419):
            if internal_retries > 0:
                self._access_token = self._generate_access_token_using_refresh_token()
                return self.http_request(
                    method=method,
                    url_suffix=url_suffix,
                    params=params,
                    response_type=response_type,
                    data=data,
                    json_data=json_data,
                    internal_retries=internal_retries - 1,
                    **kwargs,
                )

            raise ValueError(ERRORS["GENERAL_AUTH_ERROR"].format(res.status_code))
        try:
            result = None
            if response_type == "json":
                result = res.json()
            if response_type == "content":
                result = res.content()
            if response_type == "response":
                result = res
            if response_type == "text":
                result = res.text
        except ValueError as exception:
            raise DemistoException(ERRORS["INVALID_OBJECT"].format(response_type, res.text), exception, res)
        # If the success response is received, then return it.
        if res.status_code in (200, 201):
            return result

        # Return None if the response status code does not indicate success.
        return None

    def _generate_token(self) -> str:
        """
        Generates access token.

        :return: The access token.
        :rtype: str
        """
        demisto.info("Generating new access token.")
        headers = {
            "Accept": "application/json",
            "X-Api-Key": self.api_key,
            "X-XMCYBER-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION,
        }

        response = self._http_request(
            method="POST",
            url_suffix=ENDPOINTS["AUTH_ENDPOINT"],
            headers=headers,
            retries=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            ok_codes=OK_CODES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            raise_on_status=True,
            resp_type="response",
        )

        if response.status_code in (401,):
            raise ValueError(ERRORS["GENERAL_AUTH_ERROR"].format(response.status_code))

        try:
            result = response.json()
        except ValueError as exception:
            raise DemistoException(ERRORS["INVALID_OBJECT"].format("json", response.text), exception, response)

        access_token = result.get("accessToken", "")
        refresh_token = result.get("refreshToken", "")
        set_integration_context({"access_token": access_token, "refresh_token": refresh_token})
        return access_token

    def _generate_access_token_using_refresh_token(self) -> str:
        """
        Generates a new access token using the refresh token.

        :return: The access token.
        :rtype: str
        """
        context = get_integration_context()
        refresh_token = context.get("refresh_token")
        demisto.info("Generating new access token using refresh token.")

        if not refresh_token:
            demisto.debug("Refresh token not found in integration context.")
            return self._generate_token()

        headers = {"Accept": "application/json", "X-XMCYBER-CONNECTOR-NAME-VERSION": CONNECTOR_NAME_VERSION}
        payload = {"refreshToken": refresh_token}

        response = self._http_request(
            method="POST",
            url_suffix=ENDPOINTS["REFRESH_TOKEN_ENDPOINT"],
            headers=headers,
            data=payload,
            ok_codes=OK_CODES + (400,),
            retries=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_status=True,
            resp_type="response",
        )

        if response.status_code in (400, 401, 419):
            return self._generate_token()
        elif response.status_code in (200,):
            try:
                result = response.json()
            except ValueError as exception:
                raise DemistoException(ERRORS["INVALID_OBJECT"].format("json", response.text), exception, response)
            access_token = result.get("accessToken", "")
            if result.get("refreshToken"):
                refresh_token = result.get("refreshToken")

            # set new access token
            set_integration_context({"access_token": access_token, "refresh_token": refresh_token})
            return access_token

        return ""

    def get_entities(self, entity_ids: list) -> Any | None:
        """
        Gets entities from the XM Cyber server.

        :param entity_ids: The IDs of the entities to return.
        :type entity_ids: list

        :return: A list of entities.
        :rtype: Any | None
        """
        params = [("names", name) for name in entity_ids]
        params.append(("format", "raw"))
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["GET_ENTITIES_ENDPOINT"],
            params=params,
            response_type="json",
        )

    def push_breach_point(self, entity_labels: dict[str, list[str]]) -> Any | None:
        """
        Pushes breach point labels to entities in XM Cyber.

        :param entity_labels: Dictionary mapping entity IDs to their labels.
        :type entity_labels: dict[str, list[str]]

        :return: The response from the API.
        :rtype: Any | None
        """
        return self.http_request(
            method="POST",
            url_suffix=ENDPOINTS["PUSH_BREACH_POINT_ENDPOINT"],
            json_data=entity_labels,
            response_type="response",
        )

    def get_security_score(self) -> Any | None:
        """
        Gets security score from the XM Cyber server.

        :return: The security score.
        :rtype: Any | None
        """
        demisto.debug(
            f"Fetching security score from {ENDPOINTS['GET_SECURITY_SCORE_ENDPOINT']} with params {REQUEST_PARAMS['SECURITY_SCORE']}"  # noqa: E501
        )
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["GET_SECURITY_SCORE_ENDPOINT"],
            params=REQUEST_PARAMS["SECURITY_SCORE"],
            response_type="json",
        )

    def get_critical_assets_by_severity(self) -> Any | None:
        """
        Gets critical assets by severity from the XM Cyber server.

        :return: The critical assets by severity.
        :rtype: Any | None
        """
        demisto.debug(
            f"Fetching critical assets by severity from {ENDPOINTS['GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT']} with params {REQUEST_PARAMS['CRITICAL_ASSETS']}"  # noqa: E501
        )
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["GET_CRITICAL_ASSETS_BY_SEVERITY_ENDPOINT"],
            params=REQUEST_PARAMS["CRITICAL_ASSETS"],
            response_type="json",
        )

    def get_choke_points_by_severity(self) -> Any | None:
        """
        Gets choke points by severity from the XM Cyber server.

        :return: The choke points by severity.
        :rtype: Any | None
        """
        demisto.debug(
            f"Fetching choke points by severity from {ENDPOINTS['GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT']} with params {REQUEST_PARAMS['CHOKE_POINTS']}"  # noqa: E501
        )
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["GET_CHOKE_POINTS_BY_SEVERITY_ENDPOINT"],
            params=REQUEST_PARAMS["CHOKE_POINTS"],
            response_type="json",
        )

    def get_compromising_exposures(self) -> Any | None:
        """
        Gets compromising exposures from the XM Cyber server.

        :return: The compromising exposures.
        :rtype: Any | None
        """
        demisto.debug(
            f"Fetching compromising exposures from {ENDPOINTS['GET_COMPROMISING_EXPOSURES_ENDPOINT']} with params {REQUEST_PARAMS['COMPROMISING_EXPOSURES']}"  # noqa: E501
        )
        return self.http_request(
            method="GET",
            url_suffix=ENDPOINTS["GET_COMPROMISING_EXPOSURES_ENDPOINT"],
            params=REQUEST_PARAMS["COMPROMISING_EXPOSURES"],
            response_type="json",
        )


""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: dict) -> dict:
    """
    Trim spaces from values of the args Dict.

    :param args: The args Dict to trim spaces from.
    :type args: dict

    :return: The args Dict after trimming spaces.
    :rtype: dict
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()
        val_list = argToList(val)
        if len(val_list) > 1:
            val_list = [item.strip() for item in val_list if item.strip()]
            args[key] = ",".join(val_list)
    return args


def prepare_entity_data_for_hr(entity_data: dict) -> dict | None:
    """
    Prepare entity data for human-readable output.

    :param entity_data: The entity data from API response.
    :type entity_data: dict

    :return: Processed entity data or None if invalid.
    :rtype: dict | None
    """
    entity_id = entity_data.get("id", "")
    entity_name = entity_data.get("name", "")
    if not entity_id:
        demisto.debug(ERRORS["MISSING_ENTITY_ID"].format(entity_name))
        return None

    entity_labels = entity_data.get("xmLabels", [])
    labels = ", ".join([label.get("id", "") for label in entity_labels if label.get("id")])
    risk_score_info = f"{entity_data.get('riskScoreLevel', 'Unknown')} ({entity_data.get('riskScore', 0)})"
    choke_point_score_info = f"{entity_data.get('chokePointScoreLevel', 'Unknown')} ({entity_data.get('chokePointScore', 0)})"

    hr_output = {
        "ID": entity_id,
        "Name": entity_name,
        "Type": entity_data.get("type", ""),
        "Compromise Risk Score": risk_score_info,
        "Choke Point Score": choke_point_score_info,
        "Imported Attributes": ", ".join(entity_data.get("importedLabels", [])),
        "Labels": labels,
        "Affected Unique Entities": entity_data.get("affectedUniqueEntities", 0),
        "Enabled": entity_data.get("isEnabled", ""),
        "Display Name": entity_data.get("displayName", ""),
        "Domain Name": entity_data.get("domainName", ""),
        "Last Logon Date": entity_data.get("lastLogon", ""),
        "Last Password Set Date": entity_data.get("pwdLastSet", ""),
        "Account Type": entity_data.get("account_type", ""),
        "OS Type": entity_data.get("osType", ""),
        "OS Name": entity_data.get("os", {}).get("name", ""),
        "SID": entity_data.get("sid", ""),
        "Collected At": entity_data.get("collectedAt", ""),
    }

    return hr_output


def prepare_context_hr_for_enrich_incident_command(response: list[dict]) -> tuple[list[dict], str]:
    """
    Prepare context and human readable output for enrich incident command.

    :param response: The response from the API call.
    :type response: list[dict]

    :return: A tuple containing the context and human readable output.
    :rtype: tuple[list[dict], str]
    """
    outputs, hr_data = [], []

    for entity_data in response:
        risk_score = entity_data.get("riskScore", 0)
        choke_point_score = entity_data.get("chokePointScore", 0)
        entity_data["riskScore"] = max(risk_score, 0) if isinstance(risk_score, int | float) else risk_score
        entity_data["chokePointScore"] = (
            max(choke_point_score, 0) if isinstance(choke_point_score, int | float) else choke_point_score
        )
        hr_output = prepare_entity_data_for_hr(entity_data)

        if hr_output:
            outputs.append(remove_empty_elements(entity_data))
            hr_data.append(hr_output)

    readable_output = tableToMarkdown("Entity Information", hr_data, removeNull=True, sort_headers=False)

    return outputs, readable_output


def convert_string(value: str) -> str | int | float | bool:
    """
    Convert string to appropriate type (int, float, bool, or keep as string).

    :param value: The string value to convert.
    :type value: str

    :return: Converted value.
    :rtype: str | int | float | bool
    """
    # Try numeric conversion
    try:
        return float(value) if "." in value else int(value)
    except ValueError:
        pass

    # Try boolean conversion
    try:
        return argToBoolean(value)
    except ValueError:
        return value


def validate_push_breach_point_command_args(parameter: str, operator: str, value: str) -> Any:
    """
    Validate args for push breach point command.

    :param parameter: The parameter to check.
    :type parameter: str
    :param operator: The comparison operator.
    :type operator: str
    :param value: The value to compare.
    :type value: str

    :return: The converted value.
    :rtype: Any
    """
    # Validate parameter
    if parameter.lower() not in POSSIBLE_PARAMETERS:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format(parameter, ", ".join(list(POSSIBLE_PARAMETERS.values()))))

    # Validate operator
    if operator.lower() not in POSSIBLE_OPERATORS:
        raise ValueError(ERRORS["INVALID_COMMAND_ARG_VALUE"].format(operator, ", ".join(POSSIBLE_OPERATORS_VALUES)))

    # For "All" parameter, skip further validation
    if parameter.lower() == "all":
        return value

    # Validate operator for entityID
    if parameter.lower() in EQUALITY_PARAMETERS and operator.lower() not in EQUALITY_OPERATORS:
        raise ValueError(ERRORS["EQUALITY_INCORRECT_OPERATOR"].format(POSSIBLE_PARAMETERS.get(parameter.lower())))

    # Validate operator for list parameters
    if parameter.lower() in STRINGIFIED_LIST_PARAMETERS:
        if operator.lower() not in CONTAINS_OPERATORS:
            raise ValueError(ERRORS["CONTAINS_INCORRECT_PARAMETER"].format(POSSIBLE_PARAMETERS.get(parameter.lower())))
    else:
        if operator.lower() in CONTAINS_OPERATORS:
            raise ValueError(ERRORS["CONTAINS_INCORRECT_OPERATOR"].format(POSSIBLE_PARAMETERS.get(parameter.lower())))

    # Convert value based on parameter type
    if parameter.lower() in DATE_PARAMETERS:
        converted_value: Any = arg_to_datetime(  # type: ignore
            value, arg_name=POSSIBLE_PARAMETERS.get(parameter.lower())
        ).strftime(DATE_FORMAT)
    elif parameter.lower() in STRINGIFIED_LIST_PARAMETERS:
        converted_value = value
    else:
        converted_value = convert_string(value)
        # For string/bool values, only allow Equals or Not equal to
        if isinstance(converted_value, str | bool) and operator.lower() not in EQUALITY_OPERATORS:
            raise ValueError(ERRORS["INCORRECT_VALUE_TYPE"])

    return converted_value


def check_entity_matches_criteria(
    entity_data: dict,
    entity_id: str,
    parameter: str,
    operator: str,
    input_value: Any,
) -> bool:
    """
    Check if entity matches the specified criteria.

    :param entity_data: The entity data from enrichment.
    :type entity_data: dict
    :param entity_id: The entity identifier.
    :type entity_id: str
    :param parameter: The parameter to check.
    :type parameter: str
    :param operator: The comparison operator.
    :type operator: str
    :param input_value: The value to compare against.
    :type input_value: Any

    :return: True if the entity matches the criteria, False otherwise.
    :rtype: bool
    """
    # If parameter is "All", entity matches by default
    if parameter == "All":
        return True

    # Handle Label parameter
    parameter_key = PARAMETER_FIELD_MAPPING.get(parameter.lower())
    if parameter_key == "Labels":
        entity_labels = entity_data.get("xmLabels", [])
        entity_value = ", ".join([label.get("id", "") for label in entity_labels if label.get("id")])
    else:
        risk_score = entity_data.get("riskScore", 0)
        choke_point_score = entity_data.get("chokePointScore", 0)
        entity_data["riskScore"] = max(risk_score, 0) if isinstance(risk_score, int | float) else risk_score
        entity_data["chokePointScore"] = (
            max(choke_point_score, 0) if isinstance(choke_point_score, int | float) else choke_point_score
        )
        entity_value = entity_data.get(parameter_key)  # type: ignore
    if entity_value is None:
        return False

    actual_value = entity_value
    if parameter.lower() in STRINGIFIED_LIST_PARAMETERS:
        actual_value = argToList(entity_value) if isinstance(entity_value, str) else entity_value
    elif parameter.lower() in DATE_PARAMETERS:
        actual_value = (
            arg_to_datetime(entity_value).strftime(DATE_FORMAT)  # type: ignore
            if isinstance(entity_value, str)
            else entity_value
        )
    else:
        actual_value = convert_string(entity_value) if isinstance(entity_value, str) else entity_value  # type: ignore
    try:
        # Use operator function directly for proper type coercion
        operator_func: Any = POSSIBLE_OPERATORS[operator.lower()]
        result = operator_func(actual_value, input_value)

        # Handle "not contains" by negating the contains result
        result ^= operator.lower() == "not contains"
        return bool(result)
    except (TypeError, AttributeError) as e:
        demisto.debug(f"Comparison error for entity {entity_id}: {str(e)}")
        return False


def extract_security_score_data(data: dict) -> dict:
    """
    Extracts security score data from the response.

    :param data: The response data from the API call.
    :type data: dict

    :return: The security score data.
    :rtype: dict
    """
    return data.get("data", {}).get("stats", {})


def extract_choke_points_data(data: dict) -> list:
    """
    Extracts choke points data from the response.

    :param data: The response data from the API call.
    :type data: dict

    :return: The choke points data.
    :rtype: list
    """
    result = []
    for choke_point in data.get("data", {}):
        choke_point_score = choke_point.get("chokePointScore", {})
        res = choke_point_score if choke_point_score else {}
        res["name"] = choke_point.get("source_entity", {}).get("name")
        result.append(res)
    return result


def extract_compromising_exposures_data(data: dict) -> list:
    """
    Extracts compromising exposures data from the response.

    :param data: The response data from the API call.
    :type data: dict

    :return: The compromising exposures data.
    :rtype: list
    """
    total_assets = data.get("extraData", {}).get("totalAssets")
    result = []
    for compromising_exposure in data.get("data", {}):
        res = {}
        res["name"] = compromising_exposure.get("displayName")
        res["chokePoints"] = compromising_exposure.get("chokePoints")
        res["severity"] = compromising_exposure.get("severity", {}).get("level", "")
        res["complexity"] = compromising_exposure.get("complexity", {}).get("level", "")
        res["entities"] = compromising_exposure.get("entities")
        res["criticalAssets"] = compromising_exposure.get("criticalAssets")
        res["criticalAssetsAtRisk"] = round((compromising_exposure.get("criticalAssets") / total_assets) * 100)
        res["totalAssets"] = total_assets
        result.append(res)
    return result


def extract_critical_assets_data(data: dict) -> list:
    """
    Extracts critical assets data from the response.

    :param data: The response data from the API call.
    :type data: dict

    :return: The critical assets data.
    :rtype: list
    """
    result = []
    for critical_asset in data.get("data", {}):
        risk_score = critical_asset.get("riskScore", {})
        res = risk_score if risk_score else {}
        res["name"] = critical_asset.get("source_entity", {}).get("name")
        result.append(res)
    return result


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests the connection to the XM Cyber server.

    :param client: The XM Cyber client instance.
    :type client: Client

    :return: 'ok' if the test passed, otherwise an error message.
    :rtype: str
    """

    client.get_entities(entity_ids=[DEFAULT_ENTITY_VALUE])

    return "ok"


def xmcyber_enrich_incident_command(client: Client, args: dict) -> CommandResults:
    """
    Enriches the incident using XM Cyber's enrichment data for HOSTNAME and USER type entities.

    :param client: The XM Cyber client instance.
    :type client: Client
    :param args: The command arguments from XSOAR.
    :type args: dict

    :return: CommandResults object containing outputs and readable output.
    :rtype: CommandResults
    """
    entity_values = args.get("entity_values", "").strip()

    if not entity_values:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_values"))

    entity_values = argToList(entity_values)
    response = client.get_entities(entity_ids=entity_values)

    if not response:
        return CommandResults(readable_output="### No enrichment data found for the specified entities.")

    # Parse the response and prepare outputs
    outputs, hr_output = prepare_context_hr_for_enrich_incident_command(deepcopy(response))
    found_entities = []
    for output in outputs:
        entity_identifier = output.get("name", "")
        if entity_identifier:
            found_entities.append(entity_identifier.lower())

    not_found_entities = [entity for entity in entity_values if entity.lower() not in found_entities]
    if not_found_entities:
        return_warning(f"The following entities were not found: {', '.join(not_found_entities)}")

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIXES["Entity"],
        outputs_key_field="id",
        outputs=remove_empty_elements(outputs),
        readable_output=hr_output,
        raw_response=response,
    )


def xmcyber_push_breach_point_command(client: Client, args: dict) -> CommandResults:
    """
    Pushes breach point labels to XM Cyber entities based on specified criteria.

    :param client: The XM Cyber client instance.
    :type client: Client
    :param args: The command arguments from XSOAR.
    :type args: dict

    :return: CommandResults object containing outputs and readable output.
    :rtype: CommandResults
    """
    # Extract and validate required arguments
    entity_values = args.get("entity_values", "").strip()
    entity_values = argToList(entity_values)
    if not entity_values:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_values"))

    # Extract optional arguments with defaults
    attribute_name = args.get("attribute_name", DEFAULT_ATTRIBUTE_NAME).strip()
    parameter = args.get("parameter", DEFAULT_PARAMETER).strip()
    operator = args.get("operator", DEFAULT_OPERATOR).strip()
    value = args.get("value", DEFAULT_VALUE).strip()

    # Validate args
    converted_value = validate_push_breach_point_command_args(parameter, operator, value)
    parameter = POSSIBLE_PARAMETERS[parameter.lower()]

    # Get entities to evaluate
    response = client.get_entities(entity_ids=entity_values)

    if not response:
        return CommandResults(readable_output="### No enrichment data found for the specified entities.")

    # Track found entities to identify missing ones
    found_entity_identifiers: list = []

    # Process entities and check criteria
    entities_to_push: dict = {}
    no_match_entities: list[str] = []
    push_imported_labels_data: dict = {}

    for entity_data in response:
        entity_id = entity_data.get("id", "")
        entity_name = entity_data.get("name", "")
        found_entity_identifiers.append(entity_name.lower())

        if not entity_id:
            demisto.debug(ERRORS["MISSING_ENTITY_ID"].format(entity_name))
            continue

        # Check if entity matches criteria
        try:
            matches = check_entity_matches_criteria(
                entity_data,
                entity_name,
                parameter,
                operator,
                converted_value,
            )
        except ValueError as e:
            demisto.debug(f"Failed to check entity {entity_name} matches criteria: {str(e)}")
            matches = False

        if matches:
            entities_to_push.update({entity_id: entity_name})
            imported_labels: list = entity_data.get("importedLabels", [])
            if attribute_name not in imported_labels:
                imported_labels.append(attribute_name)
            push_imported_labels_data.update({entity_id: imported_labels})
        else:
            no_match_entities.append(entity_name)

    # Check for entities that were requested but not found in the response
    no_match_entities.extend([entity for entity in entity_values if entity.lower() not in found_entity_identifiers])

    context_outputs = {
        "attributeName": attribute_name,
        "userSuppliedEntities": ", ".join(sorted(entity_values)),
        "matchedEntities": ", ".join(sorted(entities_to_push.values())),
        "notMatchedEntities": ", ".join(sorted(no_match_entities)),
        "parameter": parameter,
        "operator": operator,
        "value": value,
    }

    # Push breach point labels if entities match criteria
    if entities_to_push:
        if no_match_entities:
            return_warning(f"The following entities did not match the specified criteria: {', '.join(no_match_entities)}")

        client.push_breach_point(push_imported_labels_data)
        hr_output = f"### Successfully pushed the attribute '{attribute_name}' for the following entities\n" + ", ".join(
            list(entities_to_push.values())
        )
    else:
        hr_output = "### No entities matched the specified criteria to push breach point data."

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIXES["PushBreachPoint"],
        outputs_key_field=["attributeName", "userSuppliedEntities"],
        outputs=context_outputs,
        readable_output=hr_output,
    )


def xmcyber_remove_breach_point_command(client: Client, args: dict) -> CommandResults:
    """
    Removes breach point labels from XM Cyber entities.

    :param client: The XM Cyber client instance.
    :type client: Client
    :param args: The command arguments from XSOAR.
    :type args: dict

    :return: CommandResults object containing outputs and readable output.
    :rtype: CommandResults
    """
    # Extract and validate required arguments
    entity_values = args.get("entity_values", "").strip()
    attribute_name = args.get("attribute_name", DEFAULT_ATTRIBUTE_NAME).strip()
    entity_values = argToList(entity_values)
    if not entity_values:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_values"))

    # Get entities to evaluate
    response = client.get_entities(entity_ids=entity_values)

    if not response:
        return CommandResults(readable_output="### No enrichment data found for the specified entities.")

    # Track found entities and entities to remove labels from
    found_entity_identifiers: list = []
    entities_to_remove: dict = {}
    remove_imported_labels_data: dict = {}

    for entity_data in response:
        entity_id = entity_data.get("id", "")
        entity_name = entity_data.get("name", "")
        found_entity_identifiers.append(entity_name.lower())

        if not entity_id:
            demisto.debug(ERRORS["MISSING_ENTITY_ID"].format(entity_name))
            continue

        entities_to_remove.update({entity_id: entity_name})
        imported_labels: list = entity_data.get("importedLabels", [])
        imported_labels = [label for label in imported_labels if label != attribute_name]
        remove_imported_labels_data.update({entity_id: imported_labels})

    # Identify entities that were requested but not found
    not_found_entities = [entity for entity in entity_values if entity.lower() not in found_entity_identifiers]

    context_outputs = {
        "attributeName": attribute_name,
        "userSuppliedEntities": ", ".join(sorted(entity_values)),
        "removedLabelEntities": ", ".join(sorted(entities_to_remove.values())),
    }

    # Remove breach point labels by pushing empty list for the attribute
    if entities_to_remove:
        if not_found_entities:
            return_warning(f"The following entities were not found: {', '.join(not_found_entities)}")

        client.push_breach_point(remove_imported_labels_data)
        hr_output = f"### Successfully removed the attribute '{attribute_name}' from the following entities\n" + ", ".join(
            list(entities_to_remove.values())
        )
    else:
        hr_output = "### No entities found to remove breach point label."

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIXES["RemoveBreachPoint"],
        outputs_key_field="userSuppliedEntities",
        outputs=context_outputs,
        readable_output=hr_output,
    )


def xmcyber_calculate_risk_score_command(client: Client, args: dict) -> CommandResults:
    """
    Calculates the risk score based on enrichment data of entities.

    :param client: The XM Cyber client instance.
    :type client: Client
    :param args: The command arguments from XSOAR.
    :type args: dict

    :return: CommandResults object containing outputs and readable output.
    :rtype: CommandResults
    """
    # Extract and validate required arguments
    entity_values = args.get("entity_values", "").strip()
    if not entity_values:
        raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("entity_values"))

    entity_values = argToList(entity_values)

    compromise_risk_score_weight = args.get("compromise_risk_score", "0.5").strip()
    choke_point_score_weight = args.get("choke_point_score", "0.5").strip()

    try:
        compromise_risk_score_weight = float(compromise_risk_score_weight)
    except ValueError:
        raise ValueError(ERRORS["INVALID_SCORE_VALUE"].format("compromise_risk_score"))

    try:
        choke_point_score_weight = float(choke_point_score_weight)
    except ValueError:
        raise ValueError(ERRORS["INVALID_SCORE_VALUE"].format("choke_point_score"))

    if not 0 <= compromise_risk_score_weight <= 1:
        raise ValueError(ERRORS["INVALID_SCORE_VALUE"].format("compromise_risk_score"))
    if not 0 <= choke_point_score_weight <= 1:
        raise ValueError(ERRORS["INVALID_SCORE_VALUE"].format("choke_point_score"))

    # Get entities enrichment data
    response = client.get_entities(entity_ids=entity_values)

    if not response:
        return CommandResults(readable_output="### No enrichment data found for the specified entities.")

    # Calculate risk scores across all entities
    calculated_risk_score = 0.0
    max_compromise_risk_score = 0.0
    max_choke_point_score = 0.0
    max_compromise_risk_score_level = "Unknown"
    max_choke_point_score_level = "Unknown"

    for entity_data in response:
        entity_name = entity_data.get("name", "")
        # Extract compromise risk score
        compromise_risk_score_str = entity_data.get("riskScore", 0)
        individual_calculated_risk_score = 0
        try:
            compromise_risk_score = max(float(compromise_risk_score_str), 0)
            max_compromise_risk_score = max(max_compromise_risk_score, compromise_risk_score)
        except (ValueError, TypeError):
            demisto.debug(f"Invalid Compromise Risk Score value for entity {entity_name}: {compromise_risk_score_str}")

        compromise_risk_score_level = entity_data.get("riskScoreLevel", "Unknown")
        if LEVELS_TO_SCORE.get(compromise_risk_score_level.lower(), 0) > LEVELS_TO_SCORE.get(
            max_compromise_risk_score_level.lower(), 0
        ):
            max_compromise_risk_score_level = compromise_risk_score_level

        # Extract choke point score
        choke_point_score_str = entity_data.get("chokePointScore", 0)
        try:
            choke_point_score = max(float(choke_point_score_str), 0)
            max_choke_point_score = max(max_choke_point_score, choke_point_score)
        except (ValueError, TypeError):
            demisto.debug(f"Invalid Choke Point Score value for entity {entity_name}: {choke_point_score_str}")

        choke_point_score_level = entity_data.get("chokePointScoreLevel", "Unknown")
        if LEVELS_TO_SCORE.get(choke_point_score_level.lower(), 0) > LEVELS_TO_SCORE.get(max_choke_point_score_level.lower(), 0):
            max_choke_point_score_level = choke_point_score_level

        individual_calculated_risk_score = (
            compromise_risk_score * compromise_risk_score_weight + choke_point_score * choke_point_score_weight
        )
        # Calculate the final risk score
        calculated_risk_score = max(calculated_risk_score, individual_calculated_risk_score)

    # Round to 2 decimal places
    calculated_risk_score = min(round(calculated_risk_score, 2), 100)

    # Prepare context outputs
    context_outputs = {
        "entities": ", ".join(sorted(entity_values)),
        "compromisedRiskScoreLevel": max_compromise_risk_score_level,
        "compromisedRiskScore": int(max_compromise_risk_score),
        "compromisedChokePointScoreLevel": max_choke_point_score_level,
        "compromisedChokePointScore": int(max_choke_point_score),
        "calculatedRiskScore": calculated_risk_score,
    }

    # Prepare human-readable output
    hr_data = {
        "Calculated Risk Score": calculated_risk_score,
        "Compromised Risk Score Level": max_compromise_risk_score_level,
        "Compromised Risk Score": int(max_compromise_risk_score),
        "Compromised Choke Point Level": max_choke_point_score_level,
        "Compromised Choke Point Score": int(max_choke_point_score),
    }

    readable_output = tableToMarkdown("Risk Score Calculation Results", hr_data, sort_headers=False)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIXES["CalculateRiskScore"],
        outputs_key_field="entities",
        outputs=context_outputs,
        readable_output=readable_output,
    )


def xmcyber_get_dashboard_data_command(client: Client) -> CommandResults:
    """
    Fetches dashboard data from XM Cyber.

    :param client: The XM Cyber client instance.
    :type client: Client

    :return: Dashboard data.
    :rtype: dict
    """

    integration_context = get_integration_context()
    timestamp = 0
    current_time = int(time.time())

    if integration_context.get("dashboard_timestamp"):
        timestamp = integration_context.get("dashboard_timestamp")
        dashboard_data = integration_context.get("dashboard_data", {})
        demisto.debug(f"Fetched cached dashboard timestamp from integration context: {timestamp}")
    else:
        dashboard_data = {  # type: ignore
            "SecurityScore": {},
            "ChokePoints": [],
            "CriticalAssets": [],
            "CompromisingExposures": [],
        }

    if current_time > int(timestamp) + DASHBOARD_CACHE_DURATION:
        demisto.debug(
            f"Data is old. Fetching new dashboard data from XM Cyber. Current time: {current_time}, old timestamp: {timestamp}"
        )
        security_score_data = client.get_security_score()
        choke_points_data = client.get_choke_points_by_severity()
        critical_assets_data = client.get_critical_assets_by_severity()
        compromising_exposures_data = client.get_compromising_exposures()

        dashboard_data.update(
            {
                "SecurityScore": extract_security_score_data(security_score_data),  # type: ignore
                "ChokePoints": extract_choke_points_data(choke_points_data),  # type: ignore
                "CriticalAssets": extract_critical_assets_data(critical_assets_data),  # type: ignore
                "CompromisingExposures": extract_compromising_exposures_data(compromising_exposures_data),  # type: ignore
            }
        )

        integration_context["dashboard_data"] = dashboard_data
        integration_context["dashboard_timestamp"] = current_time

        set_integration_context(integration_context)

    return CommandResults(
        outputs=dashboard_data,
        outputs_prefix=OUTPUT_PREFIXES["Dashboard"],
    )


""" MAIN FUNCTION """


def main() -> None:
    """
    Main function to parse params and run commands.
    """
    params = demisto.params()
    remove_nulls_from_dictionary(params)

    # Get integration parameters
    server_url = params.get("server_url", "").strip()
    api_key = str(dict_safe_get(params, ["credentials", "password"])).strip()
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    commands: dict = {
        "xmcyber-enrich-incident": xmcyber_enrich_incident_command,
        "xmcyber-push-breach-point": xmcyber_push_breach_point_command,
        "xmcyber-calculate-risk-score": xmcyber_calculate_risk_score_command,
        "xmcyber-remove-breach-point": xmcyber_remove_breach_point_command,
    }

    commands_without_args: dict = {
        "xmcyber-get-dashboard-data": xmcyber_get_dashboard_data_command,
    }

    try:
        if not server_url:
            raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("Server URL"))
        if not api_key:
            raise ValueError(ERRORS["REQUIRED_ARGUMENT"].format("API Key"))
        # Initialize the client
        client = Client(server_url=server_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        # Get Command args
        args = demisto.args()
        # Execute the command
        if command == "test-module":
            result = test_module(client)
            return_results(result)
        elif command in commands:
            # remove nulls from dictionary and trim space from args
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            result = commands[command](client, args)
            return_results(result)
        elif command in commands_without_args:
            result = commands_without_args[command](client)
            return_results(result)
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        error_message = f"Failed to execute {command} command.\nError: {str(e)}"
        demisto.error(traceback.format_exc())
        return_error(error_message)


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
