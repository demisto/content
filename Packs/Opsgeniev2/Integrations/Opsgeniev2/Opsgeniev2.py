import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

ALERTS_SUFFIX = "/alerts"
REQUESTS_SUFFIX = "/requests"
SCHEDULE_SUFFIX = "/schedules"

MAX_REQUESTS_POLL = demisto.params().get("max_poll_count", 5)


class Client(BaseClient):
    """
    OpsGenieV2 Client
    """

    def send_and_poll(self, **kwargs):
        """
        Given an API endpoint that returns a request handler, loop until the request is completed (status is not None)
        """
        # Send the request which will return requestid
        data = self._http_request(**kwargs)
        request_id = data.get("requestId")

        if not request_id:
            raise ConnectionError(f"Failed to send request - {data}")

        status = None
        attempts = 0
        request_status = {}
        while not status:
            # we must sleep or risk exceeding the OpsGenie API Limit.
            time.sleep(1.0)
            if attempts > MAX_REQUESTS_POLL:
                raise ConnectionError(f"Failed to complete request - max attempts {MAX_REQUESTS_POLL} reached: {data}")

            request_status = self.get_request(request_id).get("data")
            status = request_status.get("success")
            time.sleep(1)
            attempts = attempts + 1

        request_status["requestId"] = request_id
        return request_status

    def get_paged(self, limit, **kwargs):
        """
        For OpsGenie Endpoints (such as ListAlerts) that are paged, pages until limit is hit.

        args
            limit (int): Controls the max number of alerts to return
        kwargs
            sort (string): Method of sorting alerts in OpsGenie
        """
        limit = int(limit)
        data = self._http_request(**kwargs)
        paging = data.get("paging")
        # If not a paged request, simply return
        if not paging:
            return data

        result = data.get("data")
        next = paging.get("next")

        while next:
            # we must sleep or risk exceeding the OpsGenie API Limit.
            time.sleep(1.0)
            data = self._http_request(full_url=next, **kwargs)

            paging = data.get("paging")
            next = paging.get("next")

            result = result + data.get("data")

            if len(result) >= limit:
                # If we hit the limit, return.
                return result[:limit]
        return result

    def get_alert(self, alert_id):
        data = self._http_request(
            method='GET',
            url_suffix=f"{ALERTS_SUFFIX}/{alert_id}"
        )
        return data

    def ack_alert(self, command_args):
        data = self.send_and_poll(
            method='POST',
            url_suffix=f"{ALERTS_SUFFIX}/{command_args.get('alert-id')}/acknowledge",
            json_data=command_args
        )
        return data

    def list_alerts(self, limit, sort):
        """
        Lists the current alerts in OpsGenie
        """
        params = {
            "sort": sort
        }
        data = self.get_paged(
            limit,
            method='GET',
            url_suffix=ALERTS_SUFFIX,
            params=params
        )
        return data

    def create_alert(self, command_args):
        """
        initiates a http request to a test url
        """
        data = self.send_and_poll(method='POST',
                                  url_suffix=ALERTS_SUFFIX,
                                  json_data=command_args)

        return data

    def delete_alert(self, alert_id):
        data = self.send_and_poll(
            method='DELETE',
            url_suffix=ALERTS_SUFFIX + f"/{alert_id}",
        )
        return data

    def close_alert(self, command_args):
        data = self.send_and_poll(method='POST',
                                  url_suffix=f"{ALERTS_SUFFIX}/{command_args.get('alert-id')}/close",
                                  json_data=command_args)

        return data

    def list_schedules(self, limit, sort):
        params = {
            "sort": sort
        }
        data = self.get_paged(
            limit,
            method='GET',
            url_suffix=SCHEDULE_SUFFIX,
            params=params
        )
        return data

    def get_schedule(self, schedule_id):
        data = self._http_request(
            method='GET',
            url_suffix=f"{SCHEDULE_SUFFIX}/{schedule_id}"
        )
        return data

    def get_on_calls(self, schedule_id):
        data = self._http_request(
            method='GET',
            url_suffix=f"{SCHEDULE_SUFFIX}/{schedule_id}/on-calls"
        )
        return data

    def get_request(self, request_id):
        data = self._http_request(
            method='GET',
            url_suffix=f"{ALERTS_SUFFIX}/{REQUESTS_SUFFIX}/{request_id}"
        )
        return data


def list_alerts(client, limit, sort):
    result = client.list_alerts(limit, sort)
    readable_result = result
    r = CommandResults(
        outputs_prefix="OpsGenieV2.Alerts",
        outputs=readable_result,
        readable_output=tableToMarkdown("OpsGenie Alerts", readable_result, headers=["id", "message", "createdAt"]),
        raw_response=result
    )
    return r


def create_alert(client, command_args):
    """
    Creates an Alert using the opsgenie alerts API, and requests API to validate it went through.
    """
    result = client.create_alert(command_args)
    r = CommandResults(
        outputs_prefix="OpsGenieV2.CreatedAlert",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Created Alert", result),
        raw_response=result
    )
    return r


def delete_alert(client, alert_id):
    result = client.delete_alert(alert_id)
    return CommandResults(
        outputs_prefix="OpsGenieV2.DeletedAlert",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Deleted Alert", result),
        raw_response=result
    )


def get_alert(client, alert_id):
    result = client.get_alert(alert_id)
    return CommandResults(
        outputs_prefix="OpsGenieV2.Alert",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Alert", result.get("data"),
                                        headers=["message", "acknowledged", "seen", "owner", "count"]),
        raw_response=result
    )


def ack_alert(client, command_args):
    result = client.ack_alert(command_args)
    return CommandResults(
        outputs_prefix="OpsGenieV2.AckedAlert",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Ack Alert", result),
        raw_response=result
    )


def close_alert(client, command_args):
    result = client.close_alert(command_args)
    return CommandResults(
        outputs_prefix="OpsGenieV2.CloseAlert",
        outputs=result,
        readable_output=tableToMarkdown("OpsGenie Close Alert", result.get("data")),
        raw_response=result
    )


def list_schedules(client, limit, sort):
    result = client.list_schedules(limit, sort)
    return CommandResults(
        outputs_prefix="OpsGenieV2.Schedules",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Schedules", result.get("data"),
                                        headers=["description", "id", "name", "timezone"]),
        raw_response=result
    )


def get_schedule(client, schedule_id):
    result = client.get_schedule(schedule_id)
    return CommandResults(
        outputs_prefix="OpsGenieV2.Schedule",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie Schedule", result.get("data"),
                                        headers=["id", "name", "timezone"]),
        raw_response=result
    )


def get_on_calls(client, schedule_id):
    result = client.get_on_calls(schedule_id)
    return CommandResults(
        outputs_prefix="OpsGenieV2.OnCall",
        outputs=result.get("data"),
        readable_output=tableToMarkdown("OpsGenie OnCall Participants", result.get("data").get("onCallParticipants"),
                                        headers=["id", "name", "type"]),
        raw_response=result
    )


def test_module(client):
    """
    Tries to run list_alerts, returning OK if integration is working.
    """

    result = client.list_alerts(5, "createdAt")
    if result:
        return 'ok'
    else:
        return 'Failed.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/v2')

    verify_certificate = not demisto.params().get('insecure', False)

    handle_proxy()
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={
                "Authorization": f"GenieKey {token}",
            }
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)
        elif demisto.command() == 'opsgenie-list-alerts':
            limit = demisto.args().get("limit", 20)
            sort = demisto.args().get("sort", "createdAt")
            return_results(list_alerts(client, limit, sort))
        elif demisto.command() == 'opsgenie-list-schedules':
            limit = demisto.args().get("limit", 20)
            sort = demisto.args().get("sort", "createdAt")
            return_results(list_schedules(client, limit, sort))
        elif demisto.command() == "opsgenie-get-on-call":
            return_results(get_on_calls(client, demisto.args().get("schedule-id")))
        elif demisto.command() == "opsgenie-get-schedule":
            return_results(get_schedule(client, demisto.args().get("schedule-id")))
        elif demisto.command() == "opsgenie-create-alert":
            return_results(create_alert(client, demisto.args()))
        elif demisto.command() == "opsgenie-ack-alert":
            return_results(ack_alert(client, demisto.args()))
        elif demisto.command() == "opsgenie-close-alert":
            return_results(close_alert(client, demisto.args()))
        elif demisto.command() == "opsgenie-get-alert":
            return_results(get_alert(client, demisto.args().get("alert-id")))
        elif demisto.command() == "opsgenie-delete-alert":
            return_results(delete_alert(client, demisto.args().get("alert-id")))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
