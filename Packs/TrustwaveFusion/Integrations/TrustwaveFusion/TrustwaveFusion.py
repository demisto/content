"""Trustwave Fusion Integration for Cortex XSOAR"""

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any
import urllib.parse

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

# Date format for Fusion searches
FUSION_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Map Fusion priority to Demisto severity
SEVERITY_MAP = {
    "INFO": 0.5,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


TICKET_FIELDS = [
    "assetIds",
    "category",
    "createdBy",
    "createdOn",
    "customerName",
    "description",
    "findings",
    "impact",
    "notes",
    "number",
    "priority",
    "status",
    "subCategory",
    "subject",
    "type",
    "updatedOn",
    "urgency",
    "formatted_notes",
]

FINDING_FIELDS = [
    "analystNotes",
    "assetsIds",
    "childFindingIds",
    "classification",
    "createdOn",
    "customerName",
    "destination",
    "detail",
    "eventsIds",
    "id",
    "parentId",
    "priority",
    "severity",
    "source",
    "status",
    "summary",
    "type",
    "updatedOn",
]

ASSET_FIELDS = [
    "cidr",
    "createdOn",
    "customerName",
    "id",
    "ips",
    "lastActivity",
    "name",
    "networkInterfaces",
    "notes",
    "os",
    "services",
    "status",
    "tags",
    "type",
    "updatedOn",
    "uri",
]

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Trustwave Fusion API Client
    """

    def search_tickets(self, **kwargs):
        result = self._http_request(
            method="GET", url_suffix="/v2/tickets", params=kwargs
        )
        tickets = []
        if result:
            tickets = result.get("items", [])

        # add formatted_notes field
        for tkt in tickets:
            if tkt["notes"]:
                tkt["formatted_notes"] = format_notes(tkt["notes"])
            else:
                tkt["formatted_notes"] = ""
            simplify_ticket(tkt)

        return tickets

    def describe(self):
        return self._http_request(method="GET", url_suffix="/v2/describe")

    def get_ticket(self, id):
        quoted_id = urllib.parse.quote(id, safe='')
        url_suffix = f"/v2/tickets/{quoted_id}"
        try:
            ticket = self._http_request(method="GET", url_suffix=url_suffix)
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 404:
                return None
            else:
                raise

        simplify_ticket(ticket)
        if ticket["notes"]:
            ticket["formatted_notes"] = format_notes(ticket["notes"])
        else:
            ticket["formatted_notes"] = ""
        return ticket

    def add_ticket_comment(self, id, comment):
        quoted_id = urllib.parse.quote(id, safe='')
        url_suffix = f"/v1/tickets/{quoted_id}/comments"
        payload = {
            "comment": comment,
        }
        result = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            empty_valid_codes=(201,),
            return_empty_response=True,
        )
        return result

    def close_ticket(self, id, comment):
        quoted_id = urllib.parse.quote(id, safe='')
        url_suffix = f"/v1/tickets/{quoted_id}/close"
        payload = {
            "comment": comment,
        }
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            empty_valid_codes=(202,),
            return_empty_response=True,
        )

    def get_finding(self, id):
        quoted_id = urllib.parse.quote(id, safe='')
        url_suffix = f"/v2/findings/{quoted_id}"
        try:
            finding = self._http_request(method="GET", url_suffix=url_suffix)
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 404:
                return None
            else:
                raise
        simplify_finding(finding)
        return finding

    def get_asset(self, id):
        quoted_id = urllib.parse.quote(id, safe='')
        url_suffix = f"/v2/assets/{quoted_id}"

        try:
            asset = self._http_request(method="GET", url_suffix=url_suffix)
        except DemistoException as e:
            if e.res is not None and e.res.status_code == 404:
                return None
            else:
                raise
        simplify_asset(asset)
        return asset

    def search_assets(self, **kwargs):
        params = {k: v for k, v in kwargs.items() if v is not None}

        url_suffix = "/v2/assets"
        results = self._http_request(method="GET", url_suffix=url_suffix,
                                     params=params)

        if "items" not in results:
            return None
        assets = results["items"]
        for asset in assets:
            simplify_asset(asset)

        return assets

    def search_findings(self, **kwargs):
        params = {k: v for k, v in kwargs.items() if v is not None}

        url_suffix = "/v2/findings"
        results = self._http_request(method="GET", url_suffix=url_suffix,
                                     params=params)

        if "items" not in results:
            return None
        findings = results["items"]
        for finding in findings:
            simplify_finding(finding)
        return findings


''' HELPER FUNCTIONS '''


def arg_to_datestring(arg, arg_name, required=False, format=None):
    dt = arg_to_datetime(arg, arg_name, required)

    datestr = None
    if dt:
        if format is None:
            format = FUSION_DATE_FORMAT
        datestr = dt.strftime(format)
    return datestr


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={"TIMEZONE": "UTC"})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f"Invalid date: {arg_name}")

        return int(date.replace(tzinfo=timezone.utc).timestamp())
    if isinstance(arg, (int, float)):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


def format_notes(notes, limit=5):
    """Format notes json from the Fusion API"""
    results = []
    for note in notes:
        actor = note.get("actor", "")
        ts = note.get("timestamp", "")
        text = note.get("text", "")
        results.append(f"{ts} Created by: {actor}")
        results.append("NOTE:")
        for line in text.split("\n"):
            results.append(f"{line}")
        results.append("----------------")
    if results:
        results.pop()
    return "\n".join(results)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        client.describe()
        message = "ok"
    except DemistoException as e:
        if e.res is not None and e.res.status_code == 401:
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise
    return message


def fetch_incidents(client, max_results, first_fetch):
    demisto.debug(f"Fetching {max_results}, {first_fetch} {type(first_fetch)}")
    last_run = demisto.getLastRun()
    last_fetch = last_run.get("last_fetch", None)
    demisto.debug(f"last_run: {last_run}")
    if last_fetch is None:
        # if missing, use what provided via first_fetch
        last_fetch = first_fetch
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    search_since = max(first_fetch, last_fetch)
    demisto.debug(f"{first_fetch} <=> {last_fetch} == {search_since}")
    created_since = timestamp_to_datestring(search_since * 1000, FUSION_DATE_FORMAT)

    ticket_types = demisto.params().get("ticket_types")
    incidents = []
    params = {
        "pageSize": max_results,
        "createdSince": created_since,
        "sortField": "createdOn",
        "sortDescending": "false",
    }
    if ticket_types:
        params["type"] = ",".join(ticket_types)
    demisto.debug(f"params: {params}")
    tickets = client.search_tickets(**params)
    latest_timestamp = search_since
    if tickets:
        demisto.debug(f"Found {len(tickets)} tickets from Fusion")
        for tkt in tickets:
            simplify_ticket(tkt)
            incident = {
                "name": tkt["subject"],
                "occurred": tkt["createdOn"],
                "description": tkt.get("description", ""),
                "severity": SEVERITY_MAP.get(tkt.get("priority"), 0),
                "rawJSON": json.dumps(tkt),
            }
            dt = dateparser.parse(tkt["createdOn"], settings={"TIMEZONE": "UTC"})
            latest_timestamp = max(dt.timestamp(), latest_timestamp)
            incidents.append(incident)

    # One second in the future to prevent duplicates
    last_run = {"last_fetch": latest_timestamp + 1}
    demisto.setLastRun(last_run)
    demisto.incidents(incidents)


def simplify_ticket(ticket):
    if not ticket:
        return
    for f in list(ticket.keys()):
        if f not in TICKET_FIELDS:
            del ticket[f]


def simplify_finding(finding):
    if not finding:
        return

    for f in list(finding.keys()):
        if f not in FINDING_FIELDS:
            del finding[f]
    if "status" in finding:
        finding["status"].pop("code", None)


def simplify_asset(asset):
    if not asset:
        return
    for f in list(asset.keys()):
        if f not in ASSET_FIELDS:
            del asset[f]


def get_ticket_command(client, args):
    id = args.get("id")
    ticket = client.get_ticket(id)

    if ticket is None:
        return CommandResults(readable_output=f"Ticket {id} not found")

    readable = [
        "| field | value |",
        "|-|-|",
    ]
    for k, v in ticket.items():
        str_value = stringEscapeMD(formatCell(v), True, True)
        if len(str_value) > 200:
            str_value = str_value[:200] + "....[Truncated]"
        readable.append(f"| {k} | {str_value} |")

    command_results = CommandResults(
        outputs_prefix="Trustwave.Ticket",
        outputs_key_field="number",
        outputs=ticket,
        readable_output="\n".join(readable),
    )
    return command_results


def add_ticket_comment_command(client, args):
    id = args.get("id")
    comment = args.get("comment")
    client.add_ticket_comment(id, comment)

    return "Success"


def close_ticket_command(client, args):
    id = args.get("id")
    comment = args.get("comment")
    client.close_ticket(id, comment)

    return "Success"


def get_finding_command(client, args):
    id = args.get("id")
    finding = client.get_finding(id)

    if finding:
        # TODO: Add readable_output (markdown) for warroom view
        command_results = CommandResults(
            outputs_prefix="Trustwave.Finding", outputs_key_field="id", outputs=finding
        )
    else:
        command_results = CommandResults(readable_output=f"Finding {id} not found")
    return command_results


def get_asset_command(client, args):
    id = args.get("id")
    asset = client.get_asset(id)

    if asset:
        # TODO: Add readable_output (markdown) for warroom view
        command_results = CommandResults(
            outputs_prefix="Trustwave.Asset", outputs_key_field="id", outputs=asset
        )
    else:
        command_results = CommandResults(readable_output=f"Asset {id} not found")
    return command_results


def get_updated_tickets_command(client, args):
    updated_since = arg_to_datestring(args.get("since"),
                                      arg_name="since",
                                      required=True,
                                      format=FUSION_DATE_FORMAT)
    ticket_types = args.get("ticket_types", "INCIDENT")
    max_tickets = args.get("fetch_limit", 100)

    demisto.debug(f"Searching since {updated_since}")
    tickets = client.search_tickets(
        updatedSince=updated_since,
        type=ticket_types,
        pageSize=max_tickets
    )

    if tickets:
        command_results = CommandResults(
            outputs_prefix="Trustwave.Ticket", outputs_key_field="number", outputs=tickets
        )
    else:
        command_results = CommandResults(readable_output="No updated tickets found")
    return command_results


def search_findings_command(client, args):
    finding_id = args.get("id")
    limit = args.get("limit", 100)
    name = args.get("name")
    classification = args.get("classification")
    summary = args.get("summary")
    detail = args.get("detail")
    severity = args.get("severity")
    priority = args.get("priority")
    created = arg_to_datestring(args.get("created_since"),
                                arg_name="created_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)
    demisto.debug(f"created: {created}")
    updated = arg_to_datestring(args.get("updated_since"),
                                arg_name="updated_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)
    demisto.debug(f"updated: {updated}")
    findings = None
    if finding_id is not None:
        finding = client.get_finding(finding_id)
        if finding:
            findings = [finding]
    else:
        findings = client.search_findings(pageSize=limit,
                                          name=name,
                                          classification=classification,
                                          summary=summary,
                                          detail=detail,
                                          priority=priority,
                                          severity=severity,
                                          createdSince=created,
                                          updatedSince=updated,
                                          )

    if findings:
        command_results = CommandResults(
            outputs_prefix="Trustwave.Finding", outputs_key_field="id", outputs=findings
        )
    else:
        command_results = CommandResults(readable_output="No matching findings found")
    return command_results


def search_assets_command(client, args):
    demisto.debug(f"args = {args}")
    asset_id = args.get("id")
    limit = args.get("limit", 100)
    name = args.get("name")
    ips = args.get("ips")
    demisto.debug(f"ips= {ips}")
    os = args.get("os")
    tags = args.get("tags")
    port = args.get("port")
    app_proto = args.get("app_protocol")
    transport = args.get("transport")
    asset_type = args.get("type")
    created = arg_to_datestring(args.get("created_since"),
                                arg_name="created_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)

    updated = arg_to_datestring(args.get("updated_since"),
                                arg_name="updated_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)

    assets = None
    if asset_id is not None:
        asset = client.get_asset(asset_id)
        if asset:
            assets = [asset]
    else:
        assets = client.search_assets(pageSize=limit,
                                      name=name,
                                      ips=ips,
                                      os=os,
                                      tags=tags,
                                      port=port,
                                      applicationProtocol=app_proto,
                                      transportProtocol=transport,
                                      type=asset_type,
                                      createdSince=created,
                                      updatedSince=updated,
                                      )
    if assets:
        command_results = CommandResults(
            outputs_prefix="Trustwave.Asset", outputs_key_field="id", outputs=assets
        )
    else:
        command_results = CommandResults(readable_output="No matching assets found")
    return command_results


def search_tickets_command(client, args):
    demisto.debug(f"args = {args}")
    ticket_id = args.get("id")
    subject = args.get("subject")
    limit = args.get("limit", 100)
    ticket_type = args.get("type")
    status = args.get("status")
    priority = args.get("priority")
    impact = args.get("impact")
    urgency = args.get("urgency")
    created = arg_to_datestring(args.get("created_since"),
                                arg_name="created_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)

    updated = arg_to_datestring(args.get("updated_since"),
                                arg_name="updated_since",
                                required=False,
                                format=FUSION_DATE_FORMAT)

    tickets = None
    if ticket_id is not None:
        ticket = client.get_ticket(ticket_id)
        if ticket:
            tickets = [ticket]
    else:
        tickets = client.search_tickets(pageSize=limit,
                                        type=ticket_type,
                                        subject=subject,
                                        status=status,
                                        priority=priority,
                                        impact=impact,
                                        urgency=urgency,
                                        createdSince=created,
                                        updatedSince=updated,
                                        )
    if tickets:
        command_results = CommandResults(
            outputs_prefix="Trustwave.Ticket", outputs_key_field="id", outputs=tickets
        )
    else:
        command_results = CommandResults(readable_output="No matching tickets found")
    return command_results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get("apikey")
    base_url = demisto.params()["url"]

    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    first_fetch = arg_to_timestamp(
        arg=demisto.params().get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )
    max_fetch = 100
    try:
        max_fetch = int(demisto.params().get("max_fetch", "100"))
    except ValueError:
        return_error("Maximum number of incidents per fetch needs to be an integer")

    demisto.debug(f"Command being called is {demisto.command()}")
    try:

        headers: Dict = {
            "Authorization": f"Bearer {api_key}",
        }

        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            fetch_incidents(client, max_fetch, first_fetch)
        elif demisto.command() == "trustwave-get-ticket":
            return_results(get_ticket_command(client, demisto.args()))
        elif demisto.command() == "trustwave-add-ticket-comment":
            return_results(add_ticket_comment_command(client, demisto.args()))
        elif demisto.command() == "trustwave-close-ticket":
            return_results(close_ticket_command(client, demisto.args()))
        elif demisto.command() == "trustwave-get-finding":
            return_results(get_finding_command(client, demisto.args()))
        elif demisto.command() == "trustwave-get-updated-tickets":
            return_results(get_updated_tickets_command(client, demisto.args()))
        elif demisto.command() == "trustwave-get-asset":
            return_results(get_asset_command(client, demisto.args()))
        elif demisto.command() == "trustwave-search-assets":
            return_results(search_assets_command(client, demisto.args()))
        elif demisto.command() == "trustwave-search-findings":
            return_results(search_findings_command(client, demisto.args()))
        elif demisto.command() == "trustwave-search-tickets":
            return_results(search_tickets_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


''' ENTRY POINT '''


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
