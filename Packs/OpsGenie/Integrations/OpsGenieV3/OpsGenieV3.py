import demistomock as demisto
from typing import Callable, Tuple
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
INTEGRATION_NAME = 'Opsgenie'
ALERTS_SUFFIX = "alerts"
REQUESTS_SUFFIX = "requests"
SCHEDULE_SUFFIX = "schedules"
INCIDENTS_SUFFIX = "incidents"
ESCALATION_SUFFIX = "escalations"
TEAMS_SUFFIX = "teams"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
INCIDENT_TYPE = 'Incidents'
ALERT_TYPE = 'Alerts'
ALL_TYPE = 'All'

''' CLIENT CLASS '''


class NotFinished(Exception):
    pass


class Client(BaseClient):
    """
    OpsGenieV3 Client
    """

    @staticmethod
    def error_handler(res: requests.Response):
        """
        :param res: the response of the http request
        :return Exception: for 404-We want to try another polling so get_request had time for
        getting valid answer. For other errors, we are raising like http_request does.
        """
        err_msg = 'Error in API call [{}] - {}' \
            .format(res.status_code, res.reason)
        if res.status_code == 404:
            raise NotFinished(err_msg)
        try:
            # Try to parse json error response
            error_entry = res.json()
            err_msg += '\n{}'.format(json.dumps(error_entry))
            raise DemistoException(err_msg, res=res)
        except ValueError:
            err_msg += '\n{}'.format(res.text)
            raise DemistoException(err_msg, res=res)

    def get_request(self, args: dict) -> Dict:
        url_suffix = "/v1" if args.get('request_type_suffix') == INCIDENTS_SUFFIX else "/v2"
        try:
            data = self._http_request(
                method='GET',
                url_suffix=f"{url_suffix}/{args.get('request_type_suffix')}/{REQUESTS_SUFFIX}/"
                           f"{args.get('request_id')}",
                error_handler=Client.error_handler
            )
        except NotFinished:
            return {}
        return data

    def get_paged(self, args: dict):
        data = self._http_request(
            method='GET',
            url_suffix=args.get("paging")
        )
        return data

    @staticmethod
    def responders_to_json(responders: List, responder_key: str, one_is_dict: bool = False) \
            -> Dict[str, List[dict] or Dict]:
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
        json_responders = {responder_key: []}
        for responder_type, value_type, value in responders_triple:
            if responder_type == "user" and value_type == "name":
                value_type = "username"
            json_responders[responder_key].append({value_type: value, "type": responder_type})
        if len(responders_triple) == 1 and one_is_dict:
            json_responders = {responder_key: json_responders[responder_key][0]}
        return json_responders

    def create_alert(self, args: dict):
        args.update(Client.responders_to_json(args.get('responders', []), "responders"))
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}",
                                  json_data=args)

    def get_alert(self, alert_id: int):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{alert_id}"
                                  )

    def list_alerts(self, args: dict):
        if args.get("query"):
            query = args.get("query")
        else:
            query = ""
            if args.get("status", ALL_TYPE) != ALL_TYPE:
                status = args.get("status").lower()
                query = f'status={status}'
            if args.get("priority", ALL_TYPE) != ALL_TYPE:
                if query:
                    query += f' AND '
                query += f'priority={args.get("priority")}'
            if args.get("tags", []):
                if query:
                    query += f' AND '
                query += f'tag={args.get("tags")}'

        params = {
            "sort": args.get("sort"),
            "limit": args.get("limit"),
            "offset": args.get("offset"),
            "query": query
        }
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}",
                                  params=params
                                  )

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
        return self._http_request(method='POST',
                                  url_suffix=f"/v2/{ALERTS_SUFFIX}/{args.get('alert-id')}/tags",
                                  json_data=args)

    def remove_alert_tag(self, args: dict):
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

    def get_schedule(self, args: dict):
        if args.get("schedule_id") and args.get("schedule_name"):
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
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{SCHEDULE_SUFFIX}/"
                                             f"{args.get('schedule')}/on-calls",
                                  params={"scheduleIdentifierType":
                                          args.get('scheduleIdentifierType')}
                                  )

    def create_incident(self, args: dict):
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

    def list_incidents(self, args: dict):
        if args.get("query"):
            query = args.get("query")
        else:
            query = ""
            if args.get("status", ALL_TYPE) != ALL_TYPE:
                status = args.get("status").lower()
                query = f'status={status}'
            if args.get("priority", ALL_TYPE) != ALL_TYPE:
                if query:
                    query += f' AND '
                query += f'priority={args.get("priority")}'
            if args.get("tags", []):
                if query:
                    query += f' AND '
                query += f'tag={args.get("tags")}'

        params = {
            "limit": args.get("limit"),
            "offset": args.get("offset"),
            "query": query
        }
        return self._http_request(method='GET',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}",
                                  params=params
                                  )

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
        args.update(Client.responders_to_json(args.get('responders', []), "responder"))
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/responders",
                                  json_data=args)

    def add_tag_incident(self, args: dict):
        return self._http_request(method='POST',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/tags",
                                  json_data=args)

    def remove_tag_incident(self, args: dict):
        return self._http_request(method='DELETE',
                                  url_suffix=f"/v1/{INCIDENTS_SUFFIX}/"
                                             f"{args.get('incident_id')}/tags",
                                  params={"tags": args.get('tags')},
                                  json_data=args)

    def get_team(self, args: dict):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{TEAMS_SUFFIX}/{args.get('team_id')}"
                                  )

    def list_teams(self):
        return self._http_request(method='GET',
                                  url_suffix=f"/v2/{TEAMS_SUFFIX}"
                                  )


''' COMMAND FUNCTIONS '''


def get_polling_result(client: Client, args: dict) -> CommandResults:
    polling_result = run_polling_command(args=args,
                                         cmd='opsgenie-get-polling-result',
                                         results_function=client.get_request)
    if isinstance(polling_result, CommandResults):
        return polling_result
    command_result = CommandResults(
        outputs_prefix=args.get("output_prefix", "OpsGenie"),
        outputs=polling_result.get("data"),
        readable_output=tableToMarkdown("OpsGenie", polling_result.get('data')),
        raw_response=polling_result
    )
    return command_result


def get_polling_paging_result(client: Client, args: dict) -> CommandResults:
    polling_result = run_polling_command(args=args,
                                         cmd='opsgenie-get-polling-paging-result',
                                         results_function=client.get_paged)
    if isinstance(polling_result, CommandResults):
        return polling_result
    command_result = CommandResults(
        outputs_prefix=args.get("output_prefix", "OpsGenie"),
        outputs=polling_result.get("data"),
        readable_output=tableToMarkdown("OpsGenie", polling_result.get('data')),
        raw_response=polling_result
    )
    return command_result


def run_polling_command(args: dict, cmd: str, results_function: Callable,
                        action_function: Optional[Callable] = None):

    ScheduledCommand.raise_error_if_not_supported()

    if "request_id" not in args and action_function:
        command_results = action_function(args)
        request_id = command_results.get("requestId")
        if not request_id:
            raise ConnectionError(f"Failed to send request - {command_results}")
        args['request_id'] = request_id
        polling_args = {
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=int(args.get('interval_in_seconds', 5)),
            args=polling_args,
            timeout_in_seconds=int(args.get('timeout_in_seconds', 60)),
        )

        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command,
                                         readable_output=f"Waiting for request_id={request_id}",
                                         outputs_prefix=args.get("output_prefix", "OpsGenie"),
                                         outputs={"requestId": request_id})
        return command_results

    command_results = results_function(args)
    status = command_results.get("data", {}).get("success")
    if status is None:
        # schedule next poll
        polling_args = {
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=int(args.get('interval_in_seconds', 5)),
            args=polling_args,
            timeout_in_seconds=int(args.get('timeout_in_seconds', 60)),
        )

        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command,
                                         readable_output="Waiting for the polling answer come back",
                                         outputs_prefix=args.get("output_prefix", "OpsGenie"),
                                         outputs={"requestId": request_id}
                                         )
    return command_results


def run_polling_paging_command(args: dict, cmd: str, results_function: Callable,
                               action_function: Optional[Callable] = None):

    ScheduledCommand.raise_error_if_not_supported()

    interval_in_secs = int(args.get('interval_in_seconds', 5))
    result = args.get('result', [])
    limit = int(args.get('limit', 20))

    if "request_id" not in args:
        # starting new flow
        command_results = action_function(args)
        request_id = command_results.get("requestId")
        if not request_id:
            raise ConnectionError(f"Failed to send request - {command_results}")
        next_paging = command_results.get("paging", {}).get("next")
        result = result + command_results.get("data")
        if not next_paging or len(result) >= limit:
            # If not a paged request, simply return
            return command_results
        else:
            # If a paged request, return scheduled_command
            polling_args = {
                'request_id': request_id,
                'paging': next_paging,
                'result': result,
                'interval_in_seconds': interval_in_secs,
                'polling': True,
                **args
            }
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=int(args.get('interval_in_seconds', 5)),
                args=polling_args,
                timeout_in_seconds=int(args.get('timeout_in_seconds', 60)),
            )
            command_results = CommandResults(scheduled_command=scheduled_command)
            return command_results

    command_results = results_function(args)
    result = result + command_results.get("data")
    command_results['data'] = result
    next_paging = command_results.get("paging", {}).get("next")
    if not next_paging or len(result) >= limit:
        # If not a paged request, simply return
        return command_results

    if len(result) < limit:
        # schedule next poll
        args['request_id'] = command_results.get('request_id')
        args['result'] = result
        args['paging'] = next_paging
        polling_args = {
            'request_id': command_results.get('request_id'),
            'paging': next_paging,
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=int(args.get('interval_in_seconds', 5)),
            args=polling_args,
            timeout_in_seconds=int(args.get('timeout_in_seconds', 60))
        )
        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command,
                                         outputs_prefix=args.get("output_prefix", "OpsGenie"),
                                         outputs={"requestId": args.get("request_id")},
                                         readable_output="Waiting for the polling answer come back",
                                         )
    return command_results


def test_module(client: Client) -> str:
    """
    Tries to run list_alerts, returning OK if integration is working.
    """
    result = client.list_alerts({"sort": "createdAt", "limit": 5})
    if result:
        return 'ok'
    return 'Failed.'


def create_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['responders'] = argToList(args.get('responders'))
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.Alert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.create_alert,
                                         results_function=client.get_request)
    return polling_result


def get_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    alert_id = args.get("alert-id", None)
    result = client.get_alert(alert_id) if alert_id else list_alerts(client, args)
    if isinstance(result, CommandResults):
        return result
    return CommandResults(
        outputs_prefix="OpsGenie.Alert",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Alert", result.get("data")),
        raw_response=result
    )


def list_alerts(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'url_suffix': f"/v2/{ALERTS_SUFFIX}",
        'output_prefix': 'OpsGenie.Alert',
        **args
    }
    polling_result = run_polling_paging_command(args=polling_args,
                                                cmd='opsgenie-get-polling-paging-result',
                                                action_function=client.list_alerts,
                                                results_function=client.get_paged)
    if isinstance(polling_result, CommandResults):
        return polling_result
    if len(polling_result['data']) > 0:
        for result in polling_result['data']:
            result['event_type'] = ALERT_TYPE
    return polling_result


def delete_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.DeletedAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.delete_alert,
                                         results_function=client.get_request)
    return polling_result


def ack_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AckedAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.ack_alert,
                                         results_function=client.get_request)
    return polling_result


def close_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.ClosedAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.close_alert,
                                         results_function=client.get_request)
    return polling_result


def assign_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    if args.get("owner_id"):
        owner = {"id": args.get("owner_id")}
    elif args.get("owner_username"):
        owner = {"username": args.get("owner_username")}
    else:   # not args.get("owner_id") and not args.get("owner_username")
        raise DemistoException("Either owner_id or owner_username should be provided.")
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'owner': owner,
        'output_prefix': 'OpsGenie.AssignAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.assign_alert,
                                         results_function=client.get_request)
    return polling_result


def add_responder_alert(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['responders'] = argToList(args.get('responders'))
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddResponderAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.add_responder_alert,
                                         results_function=client.get_request)
    return polling_result


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
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'escalation': escalation,
        'output_prefix': 'OpsGenie.EscalateAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.escalate_alert,
                                         results_function=client.get_request)
    return polling_result


def add_alert_tag(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddTagAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.add_alert_tag,
                                         results_function=client.get_request)
    return polling_result


def remove_alert_tag(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'request_type_suffix': ALERTS_SUFFIX,
        'output_prefix': 'OpsGenie.RemoveTagAlert',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.remove_alert_tag,
                                         results_function=client.get_request)
    return polling_result


def get_alert_attachments(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_alert_attachments(args)
    return CommandResults(
        outputs_prefix="OpsGenie.Alert.Attachment",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Attachment", result.get("data")),
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
    on_call_args = {
        'request_type_suffix': SCHEDULE_SUFFIX,
        'scheduleIdentifierType': schedule_identifier_type,
        'schedule': schedule,
        **args
    }
    result = client.get_on_call(on_call_args)
    command_result = CommandResults(
        outputs_prefix="OpsGenie.Schedule.OnCall",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Schedule OnCall", result['data']),
        raw_response=result
    )
    return command_result


def create_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['responders'] = argToList(args.get('responders'))
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.Incident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.create_incident,
                                         results_function=client.get_request)
    return polling_result


def delete_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.DeletedIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.delete_incident,
                                         results_function=client.get_request)
    return polling_result


def get_incidents(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident_id = args.get("incident_id", None)
    result = client.get_incident(args) if incident_id else list_incidents(client, args)
    if isinstance(result, CommandResults):
        return result
    return CommandResults(
        outputs_prefix="OpsGenie.Incident",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Incident", result.get("data")),
        raw_response=result
    )


def list_incidents(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'url_suffix': f"/v1/{INCIDENTS_SUFFIX}",
        'output_prefix': 'OpsGenie.Incident',
        **args
    }
    polling_result = run_polling_paging_command(args=polling_args,
                                                cmd='opsgenie-get-polling-paging-result',
                                                action_function=client.list_incidents,
                                                results_function=client.get_paged)
    if isinstance(polling_result, CommandResults):
        return polling_result
    if len(polling_result['data']) > 0:
        for result in polling_result['data']:
            result['event_type'] = INCIDENT_TYPE
    return polling_result


def close_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.ClosedIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.close_incident,
                                         results_function=client.get_request)
    return polling_result


def resolve_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.ResolvedIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.resolve_incident,
                                         results_function=client.get_request)
    return polling_result


def add_responder_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['responders'] = argToList(args.get('responders'))
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddResponderIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.add_responder_incident,
                                         results_function=client.get_request)
    return polling_result


def add_tag_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.AddTagIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.add_tag_incident,
                                         results_function=client.get_request)
    return polling_result


def remove_tag_incident(client: Client, args: Dict[str, Any]) -> CommandResults:
    args['tags'] = argToList(args.get('tags'))
    polling_args = {
        'request_type_suffix': INCIDENTS_SUFFIX,
        'output_prefix': 'OpsGenie.RemoveTagIncident',
        **args
    }
    polling_result = run_polling_command(args=polling_args,
                                         cmd='opsgenie-get-polling-result',
                                         action_function=client.remove_tag_incident,
                                         results_function=client.get_request)
    return polling_result


def get_teams(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.get_team(args) if args.get("team_id") else client.list_teams()
    return CommandResults(
        outputs_prefix="OpsGenie.Team",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Team", result.get("data")),
        raw_response=result
    )


def fetch_incidents_by_type(client: Client,
                            params: Dict[str, Any],
                            incident_fetching_func: Callable,
                            now: datetime,
                            last_run: Optional[str] = None) -> List[Dict[str, Any]]:
    query = params.get('query')
    limit = int(params.get('max_fetch', 50))
    fetch_time = params.get('first_fetch', '3 days').strip()

    if not last_run:
        new_last_run = dateparser.parse(date_string=f"{fetch_time} UTC").strftime(DATE_FORMAT)
        last_run = new_last_run

    timestamp_now = int(now.timestamp())
    timestamp_last_run = int(dateparser.parse(last_run).timestamp())
    time_query = f'createdAt>={timestamp_last_run} AND createdAt<{timestamp_now}'
    params['query'] = f'{query} AND {time_query}' if query else f'{time_query}'
    params['limit'] = limit

    raw_response = incident_fetching_func(client, params).get('data')
    incidents = []
    if raw_response:
        for event in raw_response:
            incidents.append({
                'name': event.get('message'),
                'occurred': event.get('createdAt'),
                'rawJSON': json.dumps(event)
            })

    return incidents


def fetch_incidents_command(client: Client,
                            params: Dict[str, Any],
                            last_run: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict]:
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
    now = datetime.utcnow()
    incidents = []
    alerts = []
    if ALERT_TYPE in event_type or ALL_TYPE in event_type:
        alerts = fetch_incidents_by_type(client, params, list_alerts, now, last_run)
    if INCIDENT_TYPE in event_type or ALL_TYPE in event_type:
        incidents = fetch_incidents_by_type(client, params, list_incidents, now, last_run)
    return incidents + alerts, {'lastRun': now.strftime(DATE_FORMAT)}


''' MAIN FUNCTION '''


def main() -> None:
    api_key = demisto.params().get('token')
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
            'opsgenie-get-alerts': get_alerts,
            'opsgenie-delete-alert': delete_alert,
            'opsgenie-ack-alert': ack_alert,
            'opsgenie-close-alert': close_alert,
            'opsgenie-assign-alert': assign_alert,
            'opsgenie-add-responder-alert': add_responder_alert,
            'opsgenie-get-escalations': get_escalations,
            'opsgenie-escalate-alert': escalate_alert,
            'opsgenie-add-alert-tag': add_alert_tag,
            'opsgenie-remove-alert-tag': remove_alert_tag,
            'opsgenie-get-alert-attachments': get_alert_attachments,
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
            'opsgenie-get-polling-result': get_polling_result,
            'opsgenie-get-polling-paging-result': get_polling_paging_result,
        }
        command = demisto.command()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
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
