import traceback
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union

import dateutil.parser
import demistomock as demisto
import requests
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from funcy import get_in, identity, set_in

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"
USER_AGENT = (
    f"XSOAR/{get_demisto_version_as_str()} - Hackuity/1.0.0 - {get_integration_name()}"
)
T = TypeVar("T")


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(
        self,
        url: str,
        namespace: str,
        login: str,
        password: str,
        verify: bool = True,
        proxy: bool = True,
    ):
        self.namespace = namespace
        self.login = login
        self.password = password
        base_url = f"{url.rstrip('/')}/api/v1"
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

    @staticmethod
    def http_error_handler(res: requests.Response):  # pragma: no cover
        # adapted from default error handler in BaseClient._http_request
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}"
        try:
            error_entry = res.json()
            # json response
            if (reason := error_entry.get("reason")) and (
                correlationId := error_entry.get("correlationId")
            ):
                # hackuity-formatted error message
                err_msg += f"\n{reason}\ncorrelationId={correlationId}"
            else:
                # other error messages
                err_msg += "\n{}".format(json.dumps(error_entry))
        except ValueError:
            # non-json responses
            err_msg += "\n{}".format(res.text)
        raise DemistoException(err_msg, res=res)

    def http_request(
        self,
        *,
        method: str = "GET",
        url_suffix: str = "",
        json_data: Dict[str, Any] = None,
        resp_type: str = "json",
    ):  # pragma: no cover
        access_token = self.get_access_token()
        headers = {
            "authorization": f"Bearer {access_token}",
            "content-type": "application/json",
            "user-agent": USER_AGENT,
        }
        demisto.info(f"API call: HTTP {method} on {url_suffix}")
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            headers=headers,
            json_data=json_data,
            resp_type=resp_type,
            error_handler=self.http_error_handler,
        )

    def get_access_token(self) -> str:
        """Get an access token from integration cache or by loggin in"""
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        access_token_expiration = integration_context.get("access_token_expiration", 0)

        # use already existing access token if possible
        if access_token and time.time() < access_token_expiration:
            return access_token

        # log in
        demisto.info("API login")
        try:
            response = self._http_request(
                method="POST",
                url_suffix="/authentication/idp/oauth2/token",
                data={
                    "grant_type": "password",
                    "scope": self.namespace,
                    "username": self.login,
                    "password": self.password,
                },
                headers={
                    "content-type": "application/x-www-form-urlencoded",
                    "user-agent": USER_AGENT,
                },
            )
        except DemistoException as e:
            # extract error description in case of OAuth error
            try:
                error_description = e.res.json()["error_description"]
            except Exception:
                raise e  # failled to get error description
            # format error message
            raise DemistoException(
                message=f"Authentication error: {error_description}",
                exception=e.exception,
                res=e.res,
            ) from e

        set_integration_context(
            {
                # clear other keys to force refresh
                "access_token": response["access_token"],
                "access_token_expiration": int(time.time()) + response["expires_in"],
            }
        )
        return response["access_token"]

    def get_user_id(self) -> str:
        """Get the id of the user"""
        integration_context = get_integration_context()
        user_id = integration_context.get("user_id", {})

        if not user_id:
            user_id = self.fetch_user()["userId"]
            integration_context["user_id"] = user_id
            set_integration_context(integration_context)

        return user_id

    def get_vulnerability_name(self, vuln_id: str) -> Optional[str]:
        """Get the name of a vulnerability from its id"""
        # read from cache
        integration_context = get_integration_context()
        vulnerability_names = integration_context.get("vulnerability_names", {})
        if vuln_id in vulnerability_names:
            return vulnerability_names[vuln_id]

        # fetch vulnerability
        try:
            result = self.http_request(
                url_suffix=f"/namespaces/N000000101010/vulnerabilityTypes/{vuln_id}"
            )
            name = result["i18n"]["en"]["name"]
        except DemistoException:
            return None  # failed to get the name (don't save it)

        # save into cache
        vulnerability_names[vuln_id] = name
        integration_context["vulnerability_names"] = vulnerability_names
        set_integration_context(integration_context)
        return name

    def compute_asset_id(self, asset_name: str, asset_type: Optional[str]) -> str:
        request: Dict[str, Any] = {"assetAbsoluteNames": [asset_name]}
        if asset_type:
            request["assetTypes"] = [asset_type.upper()]
        response = self.http_request(
            method="POST",
            url_suffix="/search/assets",
            json_data=request,
        )
        for asset in response.get("searchAssets", []):
            if asset["assetAbsoluteName"] == asset_name:
                return asset["assetId"]
        raise ValueError("Asset not found")

    def fetch_dashboard_widgets(self) -> List[Dict[str, Any]]:
        response = self.http_request(
            method="GET",
            url_suffix=(
                f"/namespaces/{self.namespace}/dashboards/{self.get_user_id()}"
            ),
        )
        return response.get("widgets", [])

    def fetch_dashboard_widget_data(self, *, widget_id: str) -> Dict:
        try:
            response = self.http_request(
                method="GET",
                url_suffix=(
                    f"/namespaces/{self.namespace}"
                    f"/dashboards/{self.get_user_id()}"
                    f"/widgets/{widget_id}/data"
                ),
            )
        except DemistoException as e:
            if e.res.status_code == 404:
                raise ValueError(f"Widget not found: {widget_id}")
            raise
        return response.get("payload", {})

    def fetch_user(self) -> Dict[str, Any]:
        """Fetch current user. Can be used for testing access token."""
        return self.http_request(url_suffix="/echo/user")

    def fetch_findings(
        self,
        *,
        asset_name: Optional[str],
        asset_type: Optional[str],
        attribute: Optional[str],
        cvss_min: Optional[float],
        cvss_max: Optional[float],
        limit: int,
        trs_min: Optional[int],
        trs_max: Optional[int],
        vuln_type: Optional[str],
    ) -> List[Dict[str, Any]]:
        request: Dict[str, Any] = {
            "findingStatusScoreEnvironmentalMin": cvss_min,
            "findingStatusScoreEnvironmentalMax": cvss_max,
            "findingStatusScoreHyScoreMin": trs_min,
            "findingStatusScoreHyScoreMax": trs_max,
            "limit": limit,
            "offset": 0,
            "sortFields": [
                {"fieldName": "findingStatus.score.hyScore", "desc": True},
                {"fieldName": "findingStatus.score.environmental", "desc": True},
            ],
        }
        if asset_name:
            try:
                asset_id = self.compute_asset_id(asset_name, asset_type)
            except ValueError:
                return []  # asset not found so no findings
            request["assetIds"] = [asset_id]
        elif asset_type:
            raise ValueError("Asset type filter requires asset name")
        if vuln_type:
            request["vulnTypeIds"] = [vuln_type]
        if attribute:
            request["attributesValues"] = [{"value": attribute}]
        response = self.http_request(
            method="POST",
            url_suffix="/search/findings",
            json_data=request,
        )
        return response.get("searchFindings", [])

    def fetch_aggfindings(
        self,
        *,
        asset_name: Optional[str],
        asset_type: Optional[str],
        attribute: Optional[str],
        cvss_min: Optional[float],
        cvss_max: Optional[float],
        hy_global_only: bool,
        limit: int,
        trs_min: Optional[int],
        trs_max: Optional[int],
        vuln_type: Optional[str],
    ) -> List[Dict[str, Any]]:
        request: Dict[str, Any] = {
            "aggFindingNodeStatusUnignoredOpenEnvironmentalMaxMin": cvss_min,
            "aggFindingNodeStatusUnignoredOpenEnvironmentalMaxMax": cvss_max,
            "aggFindingNodeStatusUnignoredOpenHyScoreMaxMin": trs_min,
            "aggFindingNodeStatusUnignoredOpenHyScoreMaxMax": trs_max,
            "limit": limit,
            "offset": 0,
            "sortFields": [
                {
                    "fieldName": "nodeStatus.unIgnoredOpen.total.hyScore.max",
                    "desc": True,
                },
                {
                    "fieldName": "nodeStatus.unIgnoredOpen.total.environmental.max",
                    "desc": True,
                },
            ],
        }
        if hy_global_only:
            request["hyGlobalOnly"] = True
        else:
            request["byProviderOnly"] = True
            request["excludedTypes"] = ["commonVulnerabilityExposure", "hyCsvInfos"]
        if asset_name:
            try:
                asset_id = self.compute_asset_id(asset_name, asset_type)
            except ValueError:
                return []  # asset not found so no aggfindings
            request["nodeId"] = f"hy#asset/{asset_id}"
        elif asset_type:
            raise ValueError("Asset type filter requires asset name")
        if vuln_type:
            request["vulnTypeIds"] = [vuln_type]
        if attribute:
            request["aggFindingAttributesFlats"] = [{"value": attribute}]
        response = self.http_request(
            method="POST",
            url_suffix="/search/aggFindings",
            json_data=request,
        )
        return response.get("searchAggFindings", [])


""" HELPER FUNCTIONS """


def remap_item(
    item: Dict[str, Any],
    mappings: List[
        Union[
            # tuple items:
            #  1. source path
            #  2. destination path
            #  3. default value (optional)
            #  4. formatter (optional)
            Tuple[List[str], List[str]],
            Tuple[List[str], List[str], Any],
            Tuple[List[str], List[str], Any, Callable[[Any], Any]],
        ]
    ],
) -> Dict[str, Any]:
    output: Dict[str, Any] = {}
    for mapping in mappings:
        default = None
        formatter = identity
        # mypy does not understand the len checks hence the `type: ignore` comments
        # see https://github.com/python/mypy/issues/1178
        source = mapping[0]
        destination = mapping[1]
        if len(mapping) >= 3:
            default = mapping[2]  # type: ignore
        if len(mapping) >= 4:
            formatter = mapping[3]  # type: ignore
        output = set_in(output, destination, formatter(get_in(item, source, default)))
    return output


def get_first_value(item: Optional[Dict[str, T]]) -> Optional[T]:
    if item:
        return next(iter(item.values()))
    return None


def format_date(date_str: Optional[str]) -> Optional[str]:
    """Format a date from API"""
    if date_str:
        return datetime.strftime(dateutil.parser.parse(date_str), DATE_FORMAT)
    return None


def none_or_apply(item: Optional[str], apply: Callable[[str], T]) -> Optional[T]:
    if item is None:
        return None
    return apply(item)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication"""
    # excption formating in case of authentication error
    # is already done in client.get_access_token
    set_integration_context({})  # reset cache
    client.fetch_user()
    return "ok"


def hackuity_search_findings_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    asset_name = args.get("asset_name")
    asset_type = args.get("asset_type")
    attribute = args.get("attribute")
    limit = int(args["limit"])
    cvss_min = none_or_apply(args.get("cvss_min"), float)
    cvss_max = none_or_apply(args.get("cvss_max"), float)
    vuln_type = args.get("vuln_type")
    trs_min = none_or_apply(args.get("trs_min"), int)
    trs_max = none_or_apply(args.get("trs_max"), int)
    raw_response = client.fetch_findings(
        asset_name=asset_name,
        asset_type=asset_type,
        attribute=attribute,
        cvss_min=cvss_min,
        cvss_max=cvss_max,
        limit=limit,
        trs_min=trs_min,
        trs_max=trs_max,
        vuln_type=vuln_type,
    )
    outputs = []
    for finding in raw_response:
        output = remap_item(
            finding,
            [
                (
                    ["assetId"],
                    ["Asset", "ID"],
                ),
                (
                    ["assetAbsoluteName"],
                    ["Asset", "Name"],
                ),
                (
                    ["assetType"],
                    ["Asset", "Type"],
                ),
                (
                    ["findingAttributes"],
                    ["Attributes"],
                    {},
                ),
                (
                    ["findingStatus", "score", "environmental"],
                    ["Score", "CVSS"],
                    0.0,
                ),
                (
                    ["findingId"],
                    ["ID"],
                ),
                (
                    ["findingStatus", "ignored"],
                    ["Status", "Ignored"],
                    False,
                ),
                (
                    ["findingStatus", "state"],
                    ["Status", "State"],
                ),
                (
                    ["findingStatus", "subState"],
                    ["Status", "SubState"],
                ),
                (
                    ["findingStatus", "score", "hyScore"],
                    ["Score", "TRS"],
                    0,
                ),
                (
                    ["vulnTypeId"],
                    ["VulnType", "ID"],
                ),
            ],
        )
        output["VulnType"]["Name"] = client.get_vulnerability_name(
            output["VulnType"]["ID"]
        )
        outputs.append(output)
    return CommandResults(
        outputs_prefix="Hackuity.Findings",
        outputs=outputs,
        readable_output=tableToMarkdown(
            "Findings",
            outputs,
            headers=["Asset", "VulnType", "Attributes", "Score", "Status"],
        ),
    )


def hackuity_search_vulnerabilities_command(
    client: Client, args: Dict[str, Any], hy_global_only: bool
) -> CommandResults:
    asset_name = args.get("asset_name")
    asset_type = args.get("asset_type")
    attribute = args.get("attribute")
    limit = int(args["limit"])
    cvss_min = none_or_apply(args.get("cvss_min"), float)
    cvss_max = none_or_apply(args.get("cvss_max"), float)
    vuln_type = args.get("vuln_type")
    trs_min = none_or_apply(args.get("trs_min"), int)
    trs_max = none_or_apply(args.get("trs_max"), int)
    raw_response = client.fetch_aggfindings(
        asset_name=asset_name,
        asset_type=asset_type,
        attribute=attribute,
        cvss_min=cvss_min,
        cvss_max=cvss_max,
        hy_global_only=hy_global_only,
        limit=limit,
        trs_min=trs_min,
        trs_max=trs_max,
        vuln_type=vuln_type,
    )
    outputs = []
    for aggfinding in raw_response:
        output = remap_item(
            aggfinding,
            [
                (
                    [
                        "aggExtAttribute",
                        "sharedDetailsLocal",
                        "aggFindingAttributes",
                    ],
                    ["Attributes"],
                    [],
                ),
                (
                    [
                        "nodeStatus",
                        "unIgnoredOpen",
                        "total",
                        "environmental",
                        "max",
                    ],
                    ["Score", "CVSS"],
                    0.0,
                ),
                (
                    ["aggExtAttribute", "sharedDetailsLocal", "title"],
                    ["Description"],
                ),
                (
                    ["id"],
                    ["ID"],
                ),
                (
                    ["aggExtAttribute", "firstDeliveredAt"],
                    ["Seen", "First"],
                    None,
                    format_date,
                ),
                (
                    ["nodeStatus", "unIgnoredOpen", "total", "hyScore", "max"],
                    ["Score", "TRS"],
                    0,
                ),
                (
                    ["nodeStatus", "total", "nb"],
                    ["Findings", "Total"],
                    0,
                ),
                (
                    ["nodeStatus", "unIgnoredOpen", "total", "nb"],
                    ["Findings", "Open"],
                    0,
                ),
                (
                    ["nodeStatus", "unIgnoredClosed", "total", "nb"],
                    ["Findings", "Closed"],
                    0,
                ),
                (
                    ["nodeStatus", "ignored", "nb"],
                    ["Findings", "Ignored"],
                    0,
                ),
            ],
        )
        output["VulnTypes"] = [
            {
                "ID": vuln_type,
                "Name": client.get_vulnerability_name(vuln_type),
            }
            for vuln_type in get_in(aggfinding, ["aggExtAttribute", "vulnTypeIds"], [])
        ]
        outputs.append(output)
    return CommandResults(
        outputs_prefix="Hackuity.Vulnerabilities",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"{'VulnDB' if hy_global_only else 'Provider'} vulnerabilities",
            outputs,
            headers=[
                "VulnTypes",
                "Description",
                *(["Attributes"] if hy_global_only else []),
                "Score",
                "Findings",
                "Seen",
            ],
        ),
    )


def hackuity_dashboard_widgets_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    raw_response = client.fetch_dashboard_widgets()
    outputs = [
        remap_item(
            widget,
            [
                (
                    ["id"],
                    ["ID"],
                ),
                (
                    ["params"],
                    ["Params"],
                    None,
                    get_first_value,
                ),
                (
                    ["type"],
                    ["Type"],
                ),
            ],
        )
        for widget in raw_response
    ]
    return CommandResults(
        outputs_prefix="Hackuity.Dashboard.Widgets",
        outputs=outputs,
        readable_output=tableToMarkdown(
            "Dashboard widgets",
            outputs,
            headers=["ID", "Type", "Params"],
        ),
    )


def hackuity_dashboard_data_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    widget_id = args["widget_id"]
    try:
        raw_response = client.fetch_dashboard_widget_data(widget_id=widget_id)
    except ValueError:
        return CommandResults(
            readable_output=f"Widget not found: `{widget_id}`.",
        )
    outputs = get_first_value(raw_response)
    return CommandResults(
        outputs_prefix=f"Hackuity.Dashboard.Data.{widget_id}",
        outputs=outputs,
        readable_output=tableToMarkdown(
            f"Dashboard widget data ({widget_id})",
            outputs,
        ),
    )


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions"""

    url = demisto.params()["url"]
    namespace = demisto.params()["namespace"]
    login = demisto.params()["login"]["identifier"]
    password = demisto.params()["login"]["password"]

    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    commands: Dict[str, Callable[[Client, Dict[str, str]], CommandResults]] = {
        "hackuity-dashboard-data": hackuity_dashboard_data_command,
        "hackuity-dashboard-widgets": hackuity_dashboard_widgets_command,
        "hackuity-search-findings": hackuity_search_findings_command,
        "hackuity-search-provider-vulnerabilities": partial(
            hackuity_search_vulnerabilities_command, hy_global_only=False
        ),
        "hackuity-search-vulndb-vulnerabilities": partial(
            hackuity_search_vulnerabilities_command, hy_global_only=True
        ),
    }

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            url=url,
            namespace=namespace,
            login=login,
            password=password,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f"{command} is not an existing command")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
