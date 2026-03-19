# Taegis XSoar Integration

import os
import json
from typing import Callable, Dict, Any, Optional
from pathlib import Path

import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *
from taegis_sdk_python import GraphQLService, get_config
from taegis_sdk_python.services.investigations2.types import (
    InvestigationV2,
)
from taegis_sdk_python.services.alerts.types import AlertV2

from taegis_sdk_python.services.sharelinks.types import (
    ShareLinkCreateInput,
)
from dataclasses import dataclasses_fields

# Disable insecure warnings
urllib3.disable_warnings()

pack_metadata = Path("../pack_metadata.json")
if pack_metadata.exists:
    PACK_METADATA = json.load(pack_metadata)
else:
    demisto.error("../pack_metadata.json not found...")
    PACK_METADATA = {}

PACK_NAME = PACK_METADATA.get("name", "Sophos Taegis")
PACK_CURRENT_VERSION = PACK_METADATA.get("currentVersion", "dev")

demisto.debug(f"pack name = {PACK_NAME}, pack version = {PACK_CURRENT_VERSION}")


def investigation_shareable_url(
    service: GraphQLService, investigation: InvestigationV2
) -> str:
    """Create a Taegis shareable investigation URL.

    Parameters
    ----------
    service : GraphQLService
        Taegis SDK for Python GraphQLService object.
    investigation : InvestigationV2
        The investigation object to generate a shareable URL for.

    Returns
    -------
    str
        Shareable URL created by the Sharelinks API, or ``"Not Available"``
        if the investigation is not a valid ``InvestigationV2`` instance.
    """

    if not isinstance(investigation, InvestigationV2):
        return "Not Available"

    result = service.sharelinks.mutation.create_share_link(
        ShareLinkCreateInput(
            link_ref=investigation.id,
            link_type="investigationId",
            tenant_id=investigation.tenant_id,
        )
    )

    shareable_url = (
        service.investigations.sync_url.replace("api.", "") + f"/share/{result.id}"
    )

    return shareable_url


def detection_shareable_url(service: GraphQLService, detection: AlertV2) -> str:
    """Create a Taegis shareable detection URL.

    Parameters
    ----------
    service : GraphQLService
        Taegis SDK for Python GraphQLService object.
    detection : AlertV2
        The alert object to generate a shareable URL for.

    Returns
    -------
    str
        Shareable URL created by the Sharelinks API, or ``"Not Available"``
        if the detection is not a valid ``AlertV2`` instance.
    """

    if not isinstance(detection, AlertV2):
        return "Not Available"

    result = service.sharelinks.mutation.create_share_link(
        ShareLinkCreateInput(
            link_ref=detection.id,
            link_type="alertId",
            tenant_id=detection.tenant_id,
        )
    )

    shareable_url = f'{service.core.sync_url.replace("api.", "")}/share/{result.id}'
    return shareable_url


def playbook_execution_shareable_url(
    service: GraphQLService, playbook_execution: Dict[str, Any]
) -> str:
    """Create a Taegis shareable playbook execution URL.

    Parameters
    ----------
    service : GraphQLService
        Taegis SDK for Python GraphQLService object.
    playbook_execution : Dict[str, Any]
        Playbook execution result dict containing at minimum ``"id"`` and
        ``"tenant"`` keys.

    Returns
    -------
    str
        Shareable URL created by the Sharelinks API, or ``"Not Available"``
        if ``"id"`` is not present in ``playbook_execution``.
    """

    if not "id" in playbook_execution:
        return "Not Available"

    result = service.sharelinks.mutation.create_share_link(
        ShareLinkCreateInput(
            link_ref=playbook_execution.get("id"),
            link_type="playbookExecutionId",
            tenant_id=playbook_execution.get("tenant"),
        )
    )

    shareable_url = f'{service.core.sync_url.replace("api.", "")}/share/{result.id}'
    return shareable_url


def lookup_federated_subject(service: GraphQLService) -> Dict[str, Any]:
    """Federated response for expanding the Subjects API.

    Parameters
    ----------
    service : GraphQLService
        Taegis SDK for Python GraphQLService object.

    Returns
    -------
    Dict[str, Any]
        The current subject information.
    """

    output = service.output

    # waiting Union support in GraphQLService
    if not output:
        output = """
            id
            identity {
                __typename
            }
        """

    results = service.subjects.execute_query(endpoint="currentSubject", output=output)
    return results.get("currentSubject", {})


def lookup_assignee_id(service: GraphQLService, assignee_id: str) -> str:
    """Lookup and format assignee ID for Taegis Investigations.

    Parameters
    ----------
    service : GraphQLService
        Taegis SDK for Python GraphQLService object.
    assignee_id : str
        Assignee ID to lookup.

    Returns
    -------
    str
        Formatted Assignee ID.

    Raises
    ------
    ValueError
        If the subject ID, partner mention, or user ID cannot be resolved
        from the Taegis API.
    """
    if assignee_id == "@me":
        demisto.debug("Looking up current subject...")
        subject = lookup_federated_subject(service)
        assignee_id = subject.get("id")

        if not assignee_id:
            raise ValueError(f"Could not determine Subject ID: {subject}")

        if subject.get("identity", {}).get("__typename") == "Client":
            demisto.debug("Subject is client.  Updating assignee_id with `@clients`...")
            assignee_id += "@clients"

    elif assignee_id == "@partner":
        demisto.debug("Looking up partner mention in preferences...")
        preferences = service.preferences.query.partner_preferences()

        if not preferences.mention:
            raise ValueError(f"Could not determine Partner Mention: {preferences}")

        assignee_id = f"@{preferences.mention}"

    # alias to keep the partner/organization/tenant language consistent
    elif assignee_id == "@tenant":
        assignee_id = "@customer"

    elif (
        "@" in assignee_id  # probably an email
        and not assignee_id.startswith("@")  # don't lookup submitted mentions
        and not assignee_id.endswith("@clients")  # don't lookup submitted clients
    ):
        demisto.debug("Looking up user {assignee_id} by email...")

        # search for email in subject accessible tenants
        subject = service.subjects.query.current_subject()
        users = []
        for tenant_id in subject.role_assignment_data.assigned_tenant_ids:
            demisto.debug("Looking up user {assignee_id} in {tenant_id}...")
            with service(tenant_id=tenant_id):
                users = service.users.query.tdrusers(email=assignee_id)
                if users:
                    break

        # search for email in tenant context
        if not users:
            demisto.debug("Looking up user {assignee_id} in {service.tenant_id}...")
            users = service.users.query.tdrusers(email=assignee_id)

        if users:
            demisto.debug("User {assignee_id} found. Using ID: {users[0].id}")
            assignee_id = users[0].id

            if not assignee_id:
                raise ValueError(f"Could not determine User ID: {users}")
        else:
            demisto.warning(
                f"User {assignee_id} not found.  Using ID: {assignee_id}..."
            )

    return assignee_id


# Constants
###########

DEFAULT_FIRST_FETCH_INTERVAL = "1 day"
XSOAR_CALLER_NAME = "XSoar Integration"


# Commands
##########


def add_evidence_to_investigation_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Add events, detection or query evidence to an investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    from taegis_sdk_python.services.investigations2.types import (
        AddEvidenceToInvestigationInput,
    )

    with service(output=args.get("fields")):
        results = service.investigations2.mutations.add_evidence_to_investigation(
            input_=AddEvidenceToInvestigationInput.from_dict(args)
        )

    results_table = results.to_dict()
    results_table.update(dict(url=investigation_shareable_url(service, results)))

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.addEvidenceToInvestigation",
        outputs_key_field="investigationId",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Investigation Evidence",
            results_table,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def create_comment_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Create Taegis Case Comment.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """
    from taegis_sdk_python.services.investigations2.types import (
        AddCommentToInvestigationInput,
    )

    with service(output=args.get("fields")):
        results = service.investigations2.mutations.add_comment_to_investigation(
            input_=AddCommentToInvestigationInput.from_dict(args)
        )

    results_table = results.to_dict()

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.CommentCreate",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            results_table,
            removeNull=True,
        ),
        raw_response=results,
    )

    return command_results


def create_investigation_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Create a new Taegis Investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """
    from taegis_sdk_python.services.investigations2.types import (
        CreateInvestigationInput,
    )

    with service(output=args.get("fields")):
        results = service.investigations2.mutations.create_investigation(
            input_=CreateInvestigationInput.from_dict(args)
        )

    results_table = results.to_dict()
    results_table.update(dict(url=investigation_shareable_url(service, results)))

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Investigation",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Investigation",
            results_table,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def execute_playbook_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Execute a Taegis Playbook.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    playbook_id = args.get("id")
    if not playbook_id:
        raise ValueError("Cannot execute playbook, missing playbook_id")

    fields: str = args.get("fields") or "id"
    playbook_inputs = args.get("inputs", {})

    variables = {
        "playbookInstanceId": playbook_id,
        "parameters": playbook_inputs,
    }

    results = service.core.execute_mutation(
        endpoint="executePlaybookInstance",
        variables=variables,
        output=fields,
    )

    results_table = results.get("executePlaybookInstance", {})
    results_table.update(dict(url=playbook_execution_shareable_url(service, results_table)))

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Execution",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Playbook Execution",
            results_table,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def fetch_alerts_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch a specific alert or a list of alerts based on a CQL Taegis query.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    from taegis_sdk_python.commons.alert.search import alerts_search

    with service(output=args.get("fields")):
        results_list = alerts_search(
            service=service,
            query="from alert severity >= 0.4 and status='OPEN'",
            limit=arg_to_number(args.get("limit", 10)),
            caller_name=XSOAR_CALLER_NAME,
        )

    alerts = [alert for results in results_list for alert in results.alerts.list]
    results_table = []

    for alert in alerts:
        results = alert.to_dict()
        results.update(
            dict(
                url=detection_shareable_url(
                    service,
                    alert,
                )
            )
        )
        results_table.append(results)

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Alerts",
        outputs_key_field="id",
        outputs=results_table,
        readable_output=tableToMarkdown(
            "Taegis Alerts",
            results_table,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results_list,
    )

    return command_results


def fetch_assets_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Assets based on search criteria.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    from taegis_sdk_python.services.assets.types import (
        SearchAssetsInput,
        SearchAssetsPaginationInput,
    )

    page = arg_to_number(args.get("page"), 1)
    page_size = arg_to_number(args.get("page_size"), 10)

    input_ = {}
    for input_field in dataclasses_fields(SearchAssetsInput):
        if args.get(input_field):
            input_[input_field] = args.get(input_field)
    input_ = SearchAssetsInput.from_dict(input_)

    with service(output=args.get("fields")):
        results = service.assets.query.search_assets_v2(
            input_=input_,
            pagination_input=SearchAssetsPaginationInput(
                limit=page_size,
                offset=page_size * page,
            ),
        )

    assets = [asset.to_dict() for asset in results.assets]

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Assets",
        outputs_key_field="id",
        outputs=assets,
        readable_output=tableToMarkdown(
            "Taegis Assets",
            assets,
            removeNull=True,
        ),
        raw_response=results,
    )

    return command_results


def fetch_comment_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Comment for by ID.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    with service(output=args.get("fields")):
        results = service.comments.query.comment(id=args.get("id"))

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Comment",
        outputs_key_field="id",
        outputs=results.comment,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            results.comment,
            removeNull=True,
        ),
        raw_response=results,
    )

    return command_results


def fetch_comments_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Comments for a specific investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    from taegis_sdk_python.services.investigations2.types import (
        CommentsV2Arguments,
    )

    with service(output=args.get("fields")):
        results = service.investigations2.query.comments_v2(
            arguments=CommentsV2Arguments(
                investigation_id=args.get("id"),
                page=arg_to_number(args.get("page", 1)),
                per_page=arg_to_number(args.get("page_size", 10)),
                order_by=args.get("order_direction", "DESCENDING"),
            )
        )

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Comments",
        outputs_key_field="id",
        outputs=results.comments,
        readable_output=tableToMarkdown(
            "Taegis Comments",
            results.comments,
            removeNull=True,
        ),
        raw_response=results,
    )

    return command_results


def fetch_endpoint_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Endpoint Asset.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """
    with service(output=args.get("fields")):
        results = service.assets.query.asset_endpoint_info(
            id_=args.get("id"),
        )

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Endpoint",
        outputs_key_field="hostId",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Endpoint",
            results,
            removeNull=True,
        ),
        raw_response=results,
    )

    return command_results


def fetch_investigation_alerts_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
):
    """Fetch alerts associated with a Taegis investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    with service(args.get("fields")):
        results = service.investigations.query.investigation_alerts(
            investigation_id=args.get("id"),
            page=arg_to_number(args.get("page", 0)),
            page_size=arg_to_number(args.get("page_size", 10)),
        )

    def convert_to_dict(alerts: AlertV2) -> List[Dict[str, Any]]:
        """Convert an ``AlertV2`` object to a dict with a shareable URL.

        Parameters
        ----------
        alerts : AlertV2
            Alert object to convert.

        Returns
        -------
        List[Dict[str, Any]]
            Alert as a dict with an appended ``"url"`` key.
        """
        alert = alert.to_dict()

        alert.update(
            {
                "url": detection_shareable_url(
                    service, AlertV2(id=alert["id"], tenant_id=alert["tenant_id"])
                )
            }
        )

        return alert

    alerts = [
        convert_to_dict(alert)
        for alert in set(
            [alert for alert in results.alerts or []]
            + [alert for alert in results.alerts2 or []]
        )
    ]

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationAlerts",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown(
            "Taegis Investigation Alerts",
            alerts,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def fetch_investigation_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
):
    """Fetch one or more Taegis investigations by ID or federated search query.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Supported keys:

        - ``"id"`` – fetch a single investigation by ID.
        - ``"query"`` – IQL filter string; defaults to ``"deleted_at is null"``.
        - ``"page_size"`` – maximum number of results; defaults to ``10``.
        - ``"fields"`` – GraphQL output field override.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the matched investigations.
    """
    from taegis_sdk_python.services.investigations2.types import (
        InvestigationsV2Arguments,
    )
    from taegis_sdk_python.commons.investigations.federated_search import (
        investigations_federated_search,
    )

    if id_ := args.get("id"):
        results = service.investigations2.query.investigations_v2(
            InvestigationsV2Arguments(id=id_)
        )
        investigations = results.investigations or []
    else:
        results = investigations_federated_search(
            service=service,
            query=args.get("query", "deleted_at is null"),
            limit=arg_to_number(args.get("page_size", 10)),
        )
        investigations = [
            investigation
            for result in results or []
            for investigation in result.investigations or []
        ]

    for investigation in investigations:
        shareable_url = investigation_shareable_url(service, investigation)

        investigation = investigation.to_dict()
        investigation["url"] = shareable_url

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.Investigations",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Investigations",
            results,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def fetch_playbook_execution_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Orchestration Playbook status.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """

    default_output = """
        id
        state
        instance {
          name
          playbook {
              name
          }
        }
        inputs
        createdAt
        updatedAt
        executionTime
        outputs
    """

    with service(output=args.get("fields")):
        results = service.core.execute_query(
            endpoint="playbookExecution",
            output=default_output,
            variables={"playbookExecutionId": args.get("execution_id")},
        )

    if not results:
        raise ValueError(
            f"Failed to fetch playbook execution: {results.errors[0]['message']}"
        )

    command_results = CommandResults(
        outputs_prefix="TaegisXDR.PlaybookExecution",
        outputs_key_field="id",
        outputs=results,
        readable_output=tableToMarkdown(
            "Taegis Playbook Execution",
            results,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=results,
    )

    return command_results


def fetch_users_command(
    service: GraphQLService, args: Optional[Dict[str, Any]] = None
) -> CommandResults:
    """Fetch Taegis Users.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None

    Returns
    -------
    CommandResults
        XSoar Command Results
    """
    from taegis_sdk_python.services.users.types import TDRUsersSearchInput

    user_ids = [id_ for id_ in argToList(args.get("ids", [])) if "@" not in id_]
    emails = [id_ for id_ in argToList(args.get("ids", [])) if "@" in id_]

    page = arg_to_number(args.get("page")) or 0
    page_size = arg_to_number(args.get("page_size")) or 10

    with service(output=args.get("fields")):
        if user_ids:
            users = service.users.query.tdrusers_by_ids(user_ids=user_ids)
        else:
            filters = TDRUsersSearchInput(
                status=args.get("status"),
                per_page=page_size,
                emails=emails,
                page_offset=page_size * page,
            )
            search_results = service.users.query.tdr_users_search(filters=filters)
            users = search_results.results or []

    users_table = [user.to_dict() for user in users]

    return CommandResults(
        outputs_prefix="TaegisXDR.Users",
        outputs_key_field="user_id",
        outputs=users_table,
        readable_output=tableToMarkdown(
            "Taegis Users",
            users_table,
            removeNull=True,
        ),
        raw_response=users,
    )


def isolate_asset_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Isolate a Taegis managed asset by ID.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"id"`` – asset ID to isolate.
        - ``"reason"`` – human-readable reason for the isolation.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the isolation result.

    Raises
    ------
    ValueError
        If ``"id"`` or ``"reason"`` are not provided in ``args``.
    """
    if not args.get("id"):
        raise ValueError("Cannot isolate asset, missing id")
    if not args.get("reason"):
        raise ValueError("Cannot isolate asset, missing reason")

    with service(output=args.get("fields")):
        result = service.assets.mutations.isolate_asset(
            id_=args.get("id"),
            reason=args.get("reason"),
        )

    isolation = result.to_dict()

    return CommandResults(
        outputs_prefix="TaegisXDR.AssetIsolation",
        outputs_key_field="id",
        outputs=isolation,
        readable_output=tableToMarkdown(
            "Taegis Asset Isolation",
            isolation,
            removeNull=True,
        ),
        raw_response=result,
    )


def update_alert_status_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Update the resolution status of one or more Taegis alerts.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"ids"`` – comma-separated list of alert IDs to update.
        - ``"status"`` – target resolution status (must be a valid ``AlertStatus`` value).

        Optional keys:

        - ``"reason"`` – human-readable reason for the status change.
        - ``"fields"`` – GraphQL output field override.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the update result.

    Raises
    ------
    ValueError
        If ``"ids"`` or ``"status"`` are not provided, or if ``"status"``
        is not a recognised ``AlertStatus`` value.
    """
    from taegis_sdk_python.services.alerts.types import UpdateResolutionRequestInput, AlertStatus

    if not args.get("ids"):
        raise ValueError("Alert IDs must be defined")
    if not args.get("status"):
        raise ValueError("Alert status must be defined")

    with service(output=args.get("fields")):
        result = service.alerts.mutations.alerts_service_update_resolution_info(
            in_=UpdateResolutionRequestInput(
                alert_ids=argToList(args.get("ids")),
                reason=args.get("reason", ""),
                resolution_status=AlertStatus(args.get("status")),
            )
        )

    update_result = result.to_dict()

    return CommandResults(
        outputs_prefix="TaegisXDR.AlertStatusUpdate",
        outputs_key_field="status",
        outputs=update_result,
        readable_output=tableToMarkdown(
            "Taegis Alert Update",
            update_result,
            removeNull=True,
        ),
        raw_response=result,
    )


def update_comment_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Update an existing comment on a Taegis investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"id"`` – ID of the comment to update.
        - ``"comment"`` – updated comment text.

        Optional keys:

        - ``"fields"`` – GraphQL output field override.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the updated comment.

    Raises
    ------
    ValueError
        If ``"id"`` or ``"comment"`` are not provided in ``args``.
    """
    from taegis_sdk_python.services.investigations2.types import (
        UpdateInvestigationCommentInput,
    )

    if not args.get("id"):
        raise ValueError("Cannot update comment, comment id cannot be empty")

    if not args.get("comment"):
        raise ValueError("Cannot update comment, comment cannot be empty")

    with service(output=args.get("fields")):
        result = service.investigations2.mutations.update_investigation_comment(
            input_=UpdateInvestigationCommentInput(
                comment_id=args.get("id"),
                comment=args.get("comment"),
            )
        )

    comment = result.to_dict()

    return CommandResults(
        outputs_prefix="TaegisXDR.CommentUpdate",
        outputs_key_field="id",
        outputs=comment,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            comment,
            removeNull=True,
        ),
        raw_response=result,
    )


def update_investigation_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Update fields on an existing Taegis investigation.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"id"`` – ID of the investigation to update.

        Optional keys (at least one must be provided in addition to ``"id"``):

        - Any field listed in ``INVESTIGATION_UPDATE_FIELDS``.
        - ``"tags"`` – comma-separated list of tags.
        - ``"fields"`` – GraphQL output field override.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the updated investigation.

    Raises
    ------
    ValueError
        If ``"id"`` is missing or no valid update fields are supplied.
    """
    from taegis_sdk_python.services.investigations2.types import (
        UpdateInvestigationV2Input,
    )

    input_data = UpdateInvestigationV2Input(id=args.get("id"))

    for field in INVESTIGATION_UPDATE_FIELDS:
        if args.get(field):
            if field == "tags":
                setattr(input_data, field, argToList(args[field]))
            else:
                setattr(input_data, field, args[field])

    if not input_data.id:
        raise ValueError("Cannot update investigation without id defined")
    if len(input_data.to_dict()) < 2:
        raise ValueError(
            f"No valid investigation fields provided. Supported Update Fields: {INVESTIGATION_UPDATE_FIELDS}"
        )

    result = service.investigations2.mutations.update_investigation(input_=input_data)

    investigation = result.to_dict()
    investigation["url"] = generate_id_url(env, "investigations", investigation["id"])

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationUpdate",
        outputs_key_field="id",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def archive_investigation_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Archive a Taegis investigation by ID.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"id"`` – ID of the investigation to archive.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the archived investigation.

    Raises
    ------
    ValueError
        If ``"id"`` is not provided in ``args``.
    """
    from taegis_sdk_python.services.investigations2.types import (
        ArchiveInvestigationInput,
    )

    input_data = ArchiveInvestigationInput(id=args.get("id"))

    if not input_data.id:
        raise ValueError("Cannot archive investigation, missing investigation id")

    result = service.investigations2.mutations.archive_investigation(input_=input_data)

    investigation = result.to_dict()
    investigation["url"] = generate_id_url(env, "investigations", input_data.id)

    results = CommandResults(
        outputs_prefix="TaegisXDR.ArchivedInvestigation",
        outputs_key_field="id",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation Archiving",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def unarchive_investigation_command(service: GraphQLService, args: Optional[Dict[str, Any]] = None):
    """Unarchive a previously archived Taegis investigation by ID.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService
    args : Optional[Dict[str, Any]], optional
        Command Arguments, by default None.  Required keys:

        - ``"id"`` – ID of the investigation to unarchive.

    Returns
    -------
    CommandResults
        XSoar Command Results containing the unarchived investigation.

    Raises
    ------
    ValueError
        If ``"id"`` is not provided in ``args``.
    """
    from taegis_sdk_python.services.investigations2.types import (
        ArchiveInvestigationInput,
    )

    input_data = ArchiveInvestigationInput(id=args.get("id"))

    if not input_data.id:
        raise ValueError("Cannot unarchive investigation, missing investigation id")

    result = service.investigations2.mutations.unarchive_investigation(
        input_=input_data
    )

    investigation = result.to_dict()
    investigation["url"] = generate_id_url(env, "investigations", input_data.id)

    results = CommandResults(
        outputs_prefix="TaegisXDR.UnarchivedInvestigation",
        outputs_key_field="id",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation Unarchiving",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def test_module(service: GraphQLService) -> str:
    """Validate connectivity and authentication against the Taegis API.

    Parameters
    ----------
    service : GraphQLService
        Taegis GraphQLService

    Returns
    -------
    str
        ``"ok"`` if authentication succeeds.
    """

    service.subjects.query.current_subject()

    return "ok"


""" MAIN """


def main():
    """Entry point for the Taegis XSoar integration.

    Reads the active XSOAR command and parameters, constructs a
    ``GraphQLService`` session, and dispatches to the appropriate command
    handler.  Errors are caught and surfaced via ``return_error``.
    """
    command = demisto.command()

    commands: dict[str, Callable] = {
        "fetch-incidents": fetch_incidents,
        "taegis-add-evidence-to-investigation": add_evidence_to_investigation_command,
        "taegis-create-comment": create_comment_command,
        "taegis-create-investigation": create_investigation_command,
        "taegis-create-sharelink": create_sharelink_command,
        "taegis-execute-playbook": execute_playbook_command,
        "taegis-fetch-alerts": fetch_alerts_command,
        "taegis-fetch-assets": fetch_assets_command,
        "taegis-fetch-comment": fetch_comment_command,
        "taegis-fetch-comments": fetch_comments_command,
        "taegis-fetch-endpoint": fetch_endpoint_command,
        "taegis-fetch-investigation": fetch_investigation_command,
        "taegis-fetch-investigation-alerts": fetch_investigation_alerts_command,
        "taegis-fetch-playbook-execution": fetch_playbook_execution_command,
        "taegis-fetch-users": fetch_users_command,
        "taegis-isolate-asset": isolate_asset_command,
        "taegis-update-alert-status": update_alert_status_command,
        "taegis-update-comment": update_comment_command,
        "taegis-update-investigation": update_investigation_command,
        "taegis-archive-investigation": archive_investigation_command,
        "taegis-unarchive-investigation": unarchive_investigation_command,
        "test-module": test_module,
    }

    ARGS = demisto.args()
    PARAMS = demisto.params()

    region = PARAMS.get("region", "US1")

    config = get_config()
    os.environ[config.get(region, "CLIENT_ID", fallback="CLIENT_ID")] = PARAMS.get(
        "client_id"
    )
    os.environ[config.get(region, "CLIENT_SECRET", fallback="CLIENT_SECRET")] = (
        PARAMS.get("client_secret")
    )

    service = GraphQLService(
        environment=region,
        tenant_id=ARGS.get("tenant_id"),
        proxy=PARAMS.get("proxy", False),
        ssl=not PARAMS.get("insecure", False),
        extra_headers={
            "User-Agent": f"xsoar/{PACK_CURRENT_VERSION}",
            "apollographql-client-name": "xsoar",
            "apollographql-client-version": PACK_CURRENT_VERSION,
        },
    )

    try:
        if command not in commands:
            raise NotImplementedError(
                f'The "{command}" command has not been implemented.'
            )

        if command == "test-module":
            result = commands[command](service=service)
            return_results(result)

        elif command == "fetch-incidents":
            commands[command](
                service=service,
                max_fetch=PARAMS.get("max_fetch", 15),
                first_fetch_interval=PARAMS.get(
                    "first_fetch", DEFAULT_FIRST_FETCH_INTERVAL
                ),
            )
        else:
            return_results(commands[command](service=service, args=ARGS))
    except Exception as e:
        error_string = str(e)
        demisto.error(f"Error running command: {e}")

        return_error(f"Failed to execute {command} command. Error: {error_string}")


# Entry Point
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
