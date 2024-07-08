import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests import Response
import urllib3
from collections.abc import Callable
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
DEFAULT_POLL_INTERVAL = 5
urllib3.disable_warnings()

''' CONSTANTS '''
DEFAULT_POLL_TIMEOUT = 60
INTEGRATION_NAME = 'Opsgenie'
ALERTS_SUFFIX = "alerts"
REQUESTS_SUFFIX = "requests"
SCHEDULE_SUFFIX = "schedules"
USERS_SUFFIX = "users"
INCIDENTS_SUFFIX = "incidents"
ESCALATION_SUFFIX = "escalations"
TEAMS_SUFFIX = "teams"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INCIDENT_TYPE = 'Incidents'
ALERT_TYPE = 'Alerts'
ALL_TYPE = 'All'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    OpsGenieV3 Client
    """

    def get_request(self, args: dict) -> Response:
        url_suffix = "/v1" if args.get('request_type') == INCIDENTS_SUFFIX else "/v2"

        return self._http_request(
            method='GET',
            url_suffix=f"{url_suffix}/{args.get('request_type')}/{REQUESTS_SUFFIX}/"
                       f"{args.get('request_id')}",
            ok_codes=(404, 200),
            resp_type='response')

    def get_paged(self, args: dict):
        data = self._http_request(
            method='GET',
            full_url=args.get('paging')
        )
        return data

    @staticmethod
    def responders_to_json(responders: List, responder_key: str, one_is_dict: bool = False) \
            -> Dict[str, Union[List, Dict]]:  # type: ignore
        """
        :param responders: the responders list which we get from demisto.args()
        :param responder_key: Some of the api calls need "responder" and others "responders" as a
        key in the responders jason
        :param one_is_dict: Some of the api calls need when there is one responder it as a dict
        and others as a list
        :return json_responders: reformatted respondres dict
        """
        if not responders:
            return {}
        if len(responders) % 3 != 0:
            raise DemistoException("responders must be list of: responder_type, value_type, value")
        responders_triple = list(zip(responders[::3], responders[1::3], responders[2::3]))
        json_responders = {responder_key: []}  # type: ignore
        for responder_type, value_type, value in responders_triple:
            if responder_type == "user" and value_type == "name":
                value_type = "username"
            json_responders[responder_key].append({value_type: value, "type": responder_type})
        response = json_responders
        if len(responders_triple) == 1 and one_is_dict:
            response = {responder_key: json_responders[responder_key][0]}
        return response  # type: ignore

    def create_alert(self, args: dict):
        args['responders'] = argToList(args.get('responders'))
        args['tags'] = argToList(args.get('tags'))
        if args.get('details') and not isinstance(args.get('details'), dict):
            args['details'] = {key_value.split('=')[0]: key_value.split('=')[1]
                               for key_value in argToList(args.get('details'))}

        args.update(Client.responders_to_json(args.get('responders', []), "responders"))
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}",
                                  json_data=args)

    def get_alert(self, alert_id: int):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{alert_id}"
                                  )

    def list_alerts(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        params = {
            "limit": args.get("limit"),
            "offset": args.get("offset"),
            "query": Client.build_query(args)
        }
        res = self._http_request(method='GET',
                                 url_suffix=f"/v2/{ALERTS_SUFFIX}",
                                 params=params
                                 )
        if len(res.get("data", [])) > 0:
            for result in res.get("data"):
                result['event_type'] = ALERT_TYPE
        return res

    def delete_alert(self, args: dict):
        return self._http_request(method='DELETE',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}",
                                  json_data=args)

    def ack_alert(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/"
                                             f"{args.get('alert-id')}/acknowledge",
                                  json_data=args)

    def close_alert(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/close",
                                  json_data=args)

    def assign_alert(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/assign",
                                  json_data=args)

    def add_responder_alert(self, args: dict):
        alert_id = args.get('alert-id')
        identifier = args.get('identifierType', 'id')
        args['responders'] = argToList(args.get('responders'))
        args.update(Client.responders_to_json(responders=args.get('responders', []),
                                              responder_key="responder",
                                              one_is_dict=True))
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{alert_id}/responders",
                                  params={"identifierType": identifier},
                                  json_data=args)

    def get_escalation(self, args: dict):
        if args.get("escalation_id") and args.get("escalation_name"):
            raise DemistoException("Either escalation_id or escalation_name should be provided.")
        identifier_type = "id" if args.get("escalation_id") else "name"
        escalation = args.get("escalation_id", None) or args.get("escalation_name", None)
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ESCALATION_SUFFIX}/{escalation}",
                                  params={"identifierType": identifier_type}
                                  )

    def get_escalations(self):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ESCALATION_SUFFIX}"
                                  )

    def escalate_alert(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/escalate",
                                  json_data=args)

    def add_alert_tag(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/tags",
                                  json_data=args)

    def add_alert_note(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert_id')}/notes",
                                  json_data=args)

    def add_alert_details(self, args: dict):
        if not isinstance(args.get('details'), dict):
            args['details'] = {key_value.split('=')[0]: key_value.split('=')[1]
                               for key_value in argToList(args.get('details'))}
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert_id')}/details",
                                  json_data=args)

    def remove_alert_tag(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        return self._http_request(method='DELETE',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/tags",
                                  params={"tags": args.get('tags')},
                                  json_data=args)

    def get_alert_attachments(self, args: dict):
        attachment_id = args.get("attachment_id")
        if attachment_id:
            return self._http_request(method='GET',
                                      url_suffix=f"/v2/{ALERTS_SUFFIX}/attachments/{attachment_id}")
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/"
                                             f"{args.get('alert-id')}/attachments")

    def get_alert_logs(self, args: dict):
        alert_id = args.get('alert_id')
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/"
                                             f"{alert_id}/logs")

    def get_schedule(self, args: dict):
        if not is_one_argument_given(args.get("schedule_id"), args.get("schedule_name")):
            raise DemistoException("Either schedule_id or schedule_name should be provided.")
        identifier_type = "id" if args.get("schedule_id") else "name"
        schedule = args.get("schedule_id", None) or args.get("schedule_name", None)
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{SCHEDULE_SUFFIX}/{schedule}",
                                  params={"identifierType": identifier_type}
                                  )

    def list_schedules(self):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{SCHEDULE_SUFFIX}"
                                  )

    def get_schedule_override(self, args: dict):
        identifier_type = "id" if args.get("schedule_id") else "name"
        schedule = args.get("schedule_id", None) or args.get("schedule_name", None)
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{SCHEDULE_SUFFIX}/{schedule}/"
                                             f"overrides/{args.get('override_alias')}",
                                  params={"scheduleIdentifierType": identifier_type}
                                  )

    def list_schedule_overrides(self, args: dict):
        identifier_type = "id" if args.get("schedule_id") else "name"
        schedule = args.get("schedule_id", None) or args.get("schedule_name", None)
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{SCHEDULE_SUFFIX}/{schedule}/overrides",
                                  params={"scheduleIdentifierType": identifier_type}
                                  )

    def get_on_call(self, args: dict):
        return self._http_request(method='GET', url_suffix=f"/v2/{SCHEDULE_SUFFIX}/{args.get('schedule')}/on-calls",
                                  params={"scheduleIdentifierType": args.get('scheduleIdentifierType'), "date": args.get('date')})

    def create_incident(self, args: dict):
        args['responders'] = argToList(args.get('responders'))
        args.update(Client.responders_to_json(args.get('responders', []), "responders"))
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/create",
                                  json_data=args)

    def delete_incident(self, args: dict):
        return self._http_request(method='DELETE',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/{args.get('incident_id')}",
                                  json_data=args)

    def get_incident(self, args: dict):
        return self._http_request(method='GET',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/{args.get('incident_id')}",
                                  )

    @staticmethod
    def build_query(args: dict) -> str:
        query = ""
        if args.get("query", ""):
            query = args.get("query", "")
        if args.get("is_fetch_query", False) or not args.get("query", ""):
            status = args.get("status", ALL_TYPE)
            if status != ALL_TYPE:
                query += ' AND ' if query else ''
                query += f'status={status.lower()}'
            priority = argToList(args.get("priority", [ALL_TYPE]))
            if ALL_TYPE not in priority:
                query += ' AND ' if query else ''
                priority_parsed = ' OR '.join(list(priority))
                query += f'priority: ({priority_parsed})'
            tags = argToList(args.get("tags", []))
            if tags:
                query += ' AND ' if query else ''
                tag_parsed = ' OR '.join(list(tags))
                query += f'tag: ({tag_parsed})'
        return query

    def list_incidents(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        params = {
            "limit": args.get("limit"),
            "offset": args.get("offset"),
            "query": Client.build_query(args)
        }
        res = self._http_request(method='GET',
                                 url_suffix=f"/v1/{INCIDENTS_SUFFIX}",
                                 params=params
                                 )
        if len(res.get("data", [])) > 0:
            for result in res.get("data"):
                result['event_type'] = INCIDENT_TYPE
        return res

    def close_incident(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/close",
                                  json_data=args)

    def resolve_incident(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/resolve",
                                  json_data=args)

    def add_responder_incident(self, args: dict):
        args['responders'] = argToList(args.get('responders'))
        args.update(Client.responders_to_json(args.get('responders', []), "responder"))
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/responders",
                                  json_data=args)

    def add_tag_incident(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/tags",
                                  json_data=args)

    def remove_tag_incident(self, args: dict):
        args['tags'] = argToList(args.get('tags'))
        return self._http_request(method='DELETE',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/tags",
                                  params={"tags": args.get('tags')},
                                  json_data=args)

    def invite_user(self, args):
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{USERS_SUFFIX}",
                                  json_data=args
                                  )

    def get_team(self, args: dict):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{TEAMS_SUFFIX}/{args.get('team_id')}"
                                  )

    def get_team_routing_rules(self, args: dict):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{TEAMS_SUFFIX}/{args.get('team_id')}/routing-rules"
                                  )

    def list_teams(self):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{TEAMS_SUFFIX}"
                                  )


''' HELPER FUNCTIONS '''


def is_one_argument_given(arg1, arg2):
    """
    checks that out of two arguments only one argument is set.
    :param arg1: first argument
    :param arg2: second argument
    :return: True if only one argument is set else False
    """

    return bool(arg1) ^ bool(arg2)


''' COMMAND FUNCTIONS '''


def run_polling_paging_command(args: dict, cmd: str, results_function: Callable,
                               action_function: Optional[Callable] = None) -> CommandResults:
    ScheduledCommand.raise_error_if_not_supported()

    interval_in_secs = int(args.get('interval_in_seconds', DEFAULT_POLL_INTERVAL))
    result = args.get('result', [])
    limit = int(args.get('limit', 20))

    if "request_id" not in args and action_function:
        # starting new flow
        results = action_function(args)
        request_id = results.get("requestId")
        if not request_id:
            raise ConnectionError(f"Failed to send request - {results}")
        next_paging = results.get("paging", {}).get("next")
        result = result + results.get("data")
        if not next_paging or len(result) >= limit:
            # If not a paged request, simply return
            return CommandResults(
                outputs_prefix=args.get("output_prefix", "OpsGenie"),
                outputs=results.get("data"),
                readable_output=tableToMarkdown("OpsGenie", results.get('data'),
                                                headers=['id', 'createdAt', 'acknowledged', 'count', 'status', 'tags'],
                                                removeNull=True
                                                ),
                raw_response=results
            )
        else:
            # If a paged request, return scheduled_command
            args['request_id'] = request_id
            args['result'] = result
            args['paging'] = next_paging
            polling_args = {
                'interval_in_seconds': interval_in_secs,
                'polling': True,
                **args
            }
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=int(args.get('interval_in_seconds', DEFAULT_POLL_INTERVAL)),
                args=polling_args,
                timeout_in_seconds=int(args.get('timeout_in_seconds', DEFAULT_POLL_TIMEOUT)),
            )
            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=f"Waiting for request_id={request_id}",
                                  outputs_prefix=args.get("output_prefix", "OpsGenie"),
                                  outputs={"requestId": request_id})

    results = results_function(args)
    result = result + results.get("data")
    results['data'] = result
    next_paging = results.get("paging", {}).get("next")
    if not next_paging or len(result) >= limit:
        # If not a paged request, simply return
        return CommandResults(
            outputs_prefix=args.get("output_prefix", "OpsGenie"),
            outputs=results.get("data"),
            readable_output=tableToMarkdown("OpsGenie", results.get('data'),
                                            headers=['id', 'createdAt', 'acknowledged', 'count', 'status', 'tags'],
                                            removeNull=True
                                            ),
            raw_response=results
        )

    if len(result) < limit:
        # schedule next poll
        args['request_id'] = results.get('request_id')
        args['result'] = result
        args['paging'] = next_paging
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=int(args.get('interval_in_seconds', DEFAULT_POLL_INTERVAL)),
            args=polling_args,
            timeout_in_seconds=int(args.get('timeout_in_seconds', DEFAULT_POLL_TIMEOUT))
        )
        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command,
                                         readable_output=f"Waiting for request_id={args.get('request_id')}",
                                         outputs_prefix=args.get("output_prefix", "OpsGenie"),
                                         outputs={"requestId": args.get('request_id')})
        return command_results
    return CommandResults(outputs_prefix=args.get("output_prefix", "OpsGenie"),
                          outputs=results.get("data"),
                          readable_output=tableToMarkdown("OpsGenie", results.get('data'),
                                                          headers=['id', 'createdAt', 'acknowledged', 'count', 'status',
                                                                   'tags'],
                                                          removeNull=True
                                                          ),
                          raw_response=results
                          )


def test_module(client: Client, params: dict) -> str:
    """
    Tries to run list_alerts, returning OK if integration is working.
    """
    result_list = client.list_alerts({"sort": "createdAt", "limit": 5})
    result_fetch = [{'ok': 'ok'}]
    if params.get("isFetch"):
        result_fetch, last_run = fetch_incidents_command(client, params)
    if result_list and result_fetch:
        return 'ok'
    return 'Failed.'


def create_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.Alert',
        **args
    }
    data = client.create_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def get_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get("alert-id", None)
    result = client.get_alert(alert_id) if alert_id else list_alerts(client, args)
    if isinstance(result, CommandResults):
        return result
    return CommandResults(
        outputs_prefix="OpsGenie.Alert",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Alert",
                                        result.get("data"),
                                        headers=['id', 'createdAt', 'acknowledged', 'count', 'status', 'tags'],
                                        removeNull=True
                                        ),
        raw_response=result
    )


def list_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'url_suffix': f"/v2/{ALERTS_SUFFIX}",
        'output_prefix': 'OpsGenie.Alert',
        'request_type': ALERTS_SUFFIX,
        **args
    }
    polling_result = run_polling_paging_command(args=polling_args,
                                                cmd='opsgenie-get-alerts',
                                                action_function=client.list_alerts,
                                                results_function=client.get_paged)
    return polling_result


def delete_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.DeletedAlert',
        **args
    }
    data = client.delete_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def ack_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AckedAlert',
        **args
    }
    data = client.ack_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def close_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.ClosedAlert',
        **args
    }
    data = client.close_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def assign_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    if args.get("owner_id"):
        owner = {"id": args.get("owner_id")}
    elif args.get("owner_username"):
        owner = {"username": args.get("owner_username")}
    else:  # not args.get("owner_id") and not args.get("owner_username")
        raise DemistoException("Either owner_id or owner_username should be provided.")

    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AssignAlert',
        'owner': owner,
        **args
    }
    data = client.assign_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_responder_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddResponderAlert',
        **args
    }
    data = client.add_responder_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def get_escalations(client: Client, args: Dict[str, Any]) -> CommandResults:
    escalation = args.get("escalation_id", None) or args.get("escalation_name", None)
    result = client.get_escalation(args) if escalation else client.get_escalations()
    return CommandResults(
        outputs_prefix="OpsGenie.Escalations",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Escalations", result.get("data")),
        raw_response=result
    )


def escalate_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    if args.get("escalation_id"):
        escalation = {"id": args.get("escalation_id")}
    elif args.get("escalation_name"):
        escalation = {"name": args.get("escalation_name")}
    else:  # not args.get("owner_id") and not args.get("owner_username")
        raise DemistoException("Either escalation_id or escalation_name should be provided.")
    args = {
        'request_type': ALERTS_SUFFIX,
        'escalation': escalation,
        'output_prefix': 'OpsGenie.EscalateAlert',
        **args
    }
    data = client.escalate_alert(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_alert_tag(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddTagAlert',
        **args
    }
    data = client.add_alert_tag(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_alert_note(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddAlertNote',
        **args
    }
    data = client.add_alert_note(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_alert_details(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddAlertDetails',
        **args
    }
    data = client.add_alert_details(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def remove_alert_tag(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.RemoveTagAlert',
        **args
    }
    data = client.remove_alert_tag(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def get_alert_attachments(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_alert_attachments(args)
    return CommandResults(
        outputs_prefix="OpsGenie.Alert.Attachment",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Attachment", result.get("data")),
        raw_response=result
    )


def get_alert_logs(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_alert_logs(args)
    data = result.get("data")
    return CommandResults(
        outputs_prefix="OpsGenie.AlertLogs",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Logs", data),
        raw_response=result
    )


def get_schedules(client: Client, args: Dict[str, Any]) -> CommandResults:
    schedule = args.get("schedule_id", None) or args.get("schedule_name", None)
    result = client.get_schedule(args) if schedule else client.list_schedules()
    return CommandResults(
        outputs_prefix="OpsGenie.Schedule",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Schedule", result.get("data")),
        raw_response=result
    )


def get_schedule_overrides(client: Client, args: Dict[str, Any]) -> CommandResults:
    if not args.get("schedule_id") and not args.get("schedule_name"):
        raise DemistoException("Either schedule_id or schedule_name should be provided.")
    result = client.get_schedule_override(args) if args.get("override_alias") \
        else client.list_schedule_overrides(args)
    return CommandResults(
        outputs_prefix="OpsGenie.Schedule",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Schedule", result.get("data")),
        raw_response=result
    )


def get_on_call(client: Client, args: Dict[str, Any]) -> CommandResults:
    if args.get("schedule_id"):
        schedule = args.get("schedule_id")
        schedule_identifier_type = 'id'
    elif args.get("schedule_name"):
        schedule = args.get("schedule_name")
        schedule_identifier_type = 'name'
    else:  # not args.get("schedule_id") and not args.get("schedule_name")
        raise DemistoException("Either schedule_id or schedule_name should be provided.")
    date = arg_to_datetime(args.get("starting_date"))
    on_call_args = {
        'request_type': SCHEDULE_SUFFIX,
        'scheduleIdentifierType': schedule_identifier_type,
        'schedule': schedule,
        **args
    }
    if date:
        on_call_args['date'] = date.isoformat()
        demisto.debug(f"get on call with date: {date}")
    result = client.get_on_call(on_call_args)
    command_result = CommandResults(
        outputs_prefix="OpsGenie.Schedule.OnCall",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Schedule OnCall", result.get('data')),
        raw_response=result
    )
    return command_result


def create_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.Incident',
        **args
    }
    data = client.create_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def delete_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.DeletedIncident',
        **args
    }
    data = client.delete_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def get_incidents(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", None)
    result = client.get_incident(args) if incident_id else list_incidents(client, args)
    if isinstance(result, CommandResults):
        return result
    return CommandResults(
        outputs_prefix="OpsGenie.Incident",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Incident",
                                        result.get("data"),
                                        headers=['id', 'createdAt', 'acknowledged', 'count', 'status', 'tags'],
                                        removeNull=True
                                        ),
        raw_response=result
    )


def list_incidents(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'url_suffix': f"/v1/{INCIDENTS_SUFFIX}",
        'output_prefix': 'OpsGenie.Incident',
        **args
    }
    polling_result = run_polling_paging_command(args=polling_args,
                                                cmd='opsgenie-get-incidents',
                                                action_function=client.list_incidents,
                                                results_function=client.get_paged)
    return polling_result


def close_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.ClosedIncident',
        **args
    }
    data = client.close_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def resolve_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.ResolvedIncident',
        **args
    }
    data = client.resolve_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_responder_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddResponderIncident',
        **args
    }
    data = client.add_responder_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def add_tag_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddTagIncident',
        **args
    }
    data = client.add_tag_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def remove_tag_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args = {
        'request_type': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.RemoveTagIncident',
        **args
    }
    data = client.remove_tag_incident(args)
    request_id = data.get("requestId")
    if not request_id:
        raise ConnectionError(f"Failed to send request - {data}")
    args['request_id'] = request_id
    return get_request_command(client, args)


def get_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    request_type = str(args.get('request_type'))
    results: Response = client.get_request(args)

    if results.status_code == 404:
        ScheduledCommand.raise_error_if_not_supported()
        request_id = args.get('request_id')

        raw_res = {}
        if results.content:
            try:
                raw_res = json.loads(results.content)
            except ValueError:
                demisto.error(f'Failed to parse the response content : {str(results.content)}')

        return CommandResults(
            raw_response=raw_res,
            readable_output=None if args.get('polled_once') else f"Waiting for request_id={request_id}",
            outputs_prefix=args.get("output_prefix", "OpsGenie.Request"),
            outputs=None if args.get('polled_once') else {"requestId": request_id},
            scheduled_command=ScheduledCommand(command='opsgenie-get-request',
                                               next_run_in_seconds=int(
                                                   args.get('interval_in_seconds', DEFAULT_POLL_INTERVAL)),
                                               args={**args, 'polled_once': True},
                                               timeout_in_seconds=int(
                                                   args.get('timeout_in_seconds', DEFAULT_POLL_TIMEOUT))))
    else:
        results_dict = results.json()
        outputs_prefix = args.get("output_prefix", f'OpsGenie.{request_type.capitalize()[:-1]}')
        return CommandResults(
            outputs_prefix=outputs_prefix,
            outputs=results_dict.get("data"),
            readable_output=tableToMarkdown(f"OpsGenie - {pascalToSpace(outputs_prefix.split('.')[-1])}",
                                            results_dict.get('data')),
            raw_response=results_dict
        )


def invite_user(client, args) -> CommandResults:
    args['role'] = {'name': args.get('role')}
    result = client.invite_user(args)
    return CommandResults(
        outputs_prefix="OpsGenie.Users",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Users", result.get("data")),
        raw_response=result
    )


def get_teams(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_team(args) if args.get("team_id") else client.list_teams()
    return CommandResults(
        outputs_prefix="OpsGenie.Team",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Team", result.get("data")),
        raw_response=result
    )


def get_team_routing_rules(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_team_routing_rules(args)
    data = result.get("data")
    return CommandResults(
        outputs_prefix="OpsGenie.TeamRoutingRule",
        outputs=data,
        readable_output=tableToMarkdown("OpsGenie Team Routing Rules", data),
        raw_response=result
    )


def _parse_fetch_time(fetch_time: str):
    fetch_time_date = dateparser.parse(date_string=f"{fetch_time} UTC")
    assert fetch_time_date is not None, f'could not parse {fetch_time} UTC'
    return fetch_time_date.strftime(DATE_FORMAT)


def fetch_incidents_by_type(client: Client,
                            query: Optional[str],
                            limit: Optional[int],
                            fetch_time: str,
                            status: Optional[str],
                            priority: Optional[str],
                            tags: Optional[str],
                            incident_fetching_func: Callable,
                            now: datetime,
                            last_run_dict: Optional[dict] = None):
    params: Dict[str, Any] = {}
    if not last_run_dict:
        new_last_run = _parse_fetch_time(fetch_time)
        last_run_dict = {'lastRun': new_last_run,
                         'next_page': None}

    if last_run_dict.get('next_page'):
        raw_response = client.get_paged({"paging": last_run_dict.get('next_page')})
    else:
        timestamp_now = int(now.timestamp())
        last_run = last_run_dict.get('lastRun')
        last_run_date = dateparser.parse(last_run)  # type: ignore
        assert last_run_date is not None, f'could not parse {last_run}'
        timestamp_last_run = int(last_run_date.timestamp())
        time_query = f'createdAt>{timestamp_last_run} AND createdAt<={timestamp_now}'
        params['query'] = f'{query} AND {time_query}' if query else f'{time_query}'
        params['limit'] = limit
        params['is_fetch_query'] = bool(query)
        params['status'] = status
        params["priority"] = priority
        params["tags"] = tags
        raw_response = incident_fetching_func(params)
        last_run_dict['lastRun'] = now.strftime(DATE_FORMAT)

    data = raw_response.get('data')
    incidents = []
    if data:
        for event in data:
            incidents.append({
                'name': event.get('message'),
                'occurred': event.get('createdAt'),
                'rawJSON': json.dumps(event)
            })
            if last_run_dict.get('lastRun') < event.get('createdAt'):
                last_run_dict['lastRun'] = event.get('createdAt')

    return incidents, raw_response.get("paging", {}).get("next"), last_run_dict.get('lastRun')


def _get_utc_now():
    return datetime.utcnow()


def fetch_incidents_command(client: Client,
                            params: Dict[str, Any],
                            last_run: Optional[Dict] = None) -> tuple[List[Dict[str, Any]], Dict]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        last_run: Last fetch object occurs
        params: demisto params

    Returns:
        incidents, new last_run
    """
    demisto.debug(f"Got incidentType={params.get('event_types')}")
    event_type = params.get('event_types', [ALL_TYPE])
    demisto.debug(f"Got event_type={event_type}")
    now = _get_utc_now()
    incidents = []
    alerts = []
    last_run_alerts = demisto.get(last_run, f"{ALERT_TYPE}.lastRun")
    next_page_alerts = demisto.get(last_run, f"{ALERT_TYPE}.next_page")
    last_run_incidents = demisto.get(last_run, f"{INCIDENT_TYPE}.lastRun")
    next_page_incidents = demisto.get(last_run, f"{INCIDENT_TYPE}.next_page")
    query = params.get('query')
    limit = int(params.get('max_fetch', 50))
    fetch_time = params.get('first_fetch', '3 days').strip()
    status = params.get('status')
    priority = params.get('priority')
    tags = params.get('tags')
    if ALERT_TYPE in event_type or ALL_TYPE in event_type:
        alerts, next_page_alerts, last_run_alerts = fetch_incidents_by_type(client,
                                                                            query,
                                                                            limit,
                                                                            fetch_time,
                                                                            status,
                                                                            priority,
                                                                            tags,
                                                                            client.list_alerts,
                                                                            now,
                                                                            demisto.get(last_run, f"{ALERT_TYPE}"))
    if INCIDENT_TYPE in event_type or ALL_TYPE in event_type:
        incidents, next_page_incidents, last_run_incidents = fetch_incidents_by_type(client,
                                                                                     query,
                                                                                     limit,
                                                                                     fetch_time,
                                                                                     status,
                                                                                     priority,
                                                                                     tags,
                                                                                     client.list_incidents,
                                                                                     now,
                                                                                     demisto.get(last_run, f"{INCIDENT_TYPE}"))
    return incidents + alerts, {ALERT_TYPE: {'lastRun': last_run_alerts,
                                             'next_page': next_page_alerts},
                                INCIDENT_TYPE: {'lastRun': last_run_incidents,
                                                'next_page': next_page_incidents}
                                }


''' MAIN FUNCTION '''


def main() -> None:
    api_key = demisto.params().get('credentials', {}).get("password")
    base_url = demisto.params().get('url')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "Authorization": f"GenieKey {api_key}",
            }
        )

        commands = {
            'opsgenie-create-alert': create_alert,
            'opsgenie-invite-user': invite_user,
            'opsgenie-get-alerts': get_alerts,
            'opsgenie-delete-alert': delete_alert,
            'opsgenie-ack-alert': ack_alert,
            'opsgenie-close-alert': close_alert,
            'opsgenie-assign-alert': assign_alert,
            'opsgenie-add-responder-alert': add_responder_alert,
            'opsgenie-get-escalations': get_escalations,
            'opsgenie-escalate-alert': escalate_alert,
            'opsgenie-add-alert-tag': add_alert_tag,
            'opsgenie-add-alert-note': add_alert_note,
            'opsgenie-add-alert-details': add_alert_details,
            'opsgenie-remove-alert-tag': remove_alert_tag,
            'opsgenie-get-alert-attachments': get_alert_attachments,
            'opsgenie-get-alert-logs': get_alert_logs,
            'opsgenie-get-schedules': get_schedules,
            'opsgenie-get-schedule-overrides': get_schedule_overrides,
            'opsgenie-get-on-call': get_on_call,
            'opsgenie-create-incident': create_incident,
            'opsgenie-delete-incident': delete_incident,
            'opsgenie-get-incidents': get_incidents,
            'opsgenie-close-incident': close_incident,
            'opsgenie-resolve-incident': resolve_incident,
            'opsgenie-add-responder-incident': add_responder_incident,
            'opsgenie-add-tag-incident': add_tag_incident,
            'opsgenie-remove-tag-incident': remove_tag_incident,
            'opsgenie-get-teams': get_teams,
            'opsgenie-get-team-routing-rules': get_team_routing_rules,
            'opsgenie-get-request': get_request_command
        }
        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, demisto.params()))
        elif command == 'fetch-incidents':
            incidents, new_run_date = fetch_incidents_command(client=client,
                                                              params=demisto.params(),
                                                              last_run=demisto.getLastRun().get('lastRun'))
            demisto.setLastRun(new_run_date)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
