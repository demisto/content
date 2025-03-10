import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import functools
from typing import List, Dict
from http.client import HTTPException

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class XsoarLogger:
    """Wrapper class to add a prefix to all logging statements so they can be located more easily in the logs"""

    def __init__(self, d, log_prefix=""):
        self.demisto = d
        self.log_prefix = log_prefix

    def debug(self, msg):
        demisto.debug(self.log_prefix + msg)

    def error(self, msg):
        demisto.error(self.log_prefix + msg)


class IronDefense:
    """Main class for performing plugin actions"""

    def __init__(self, demisto, session, host, port, credentials, logger, request_timeout=60.0):
        self.demisto = demisto
        self.session = session
        self.host = host
        self.port = port
        self.base_url = "https://{}:{}/IronApi".format(host, port)
        self.credentials = credentials
        self.request_timeout = request_timeout
        self.logger = logger

        self.session.headers.update({"Content-Type": "application/json"})
        self._configure_session_auth(self.demisto.getIntegrationContext())

    """ HELPER FUNCTIONS """

    def _get_jwt(self, context):
        if context is None:
            return None

        try:
            return context.get("JWT")
        except KeyError:
            return None

    def _configure_session_auth(self, data):
        self.logger.debug("Getting jwt...")

        jwt = self._get_jwt(data)
        if jwt:
            # set the auth token if it exists
            self.session.headers.update({"Authorization": "Bearer " + jwt})

    def _http_request(self, method, uri, body="{}", headers={}, params={}, auth=None, files=None):
        # Makes an API call with the given arguments
        resp = self.session.request(
            method,
            self.base_url + uri,
            data=body,
            headers=headers,
            verify=False,
            params=params,
            files=files,
            timeout=self.request_timeout,
            auth=auth,
        )
        if resp.status_code == 401:
            if auth is not None:
                # incorrect creds have been provided
                return resp

            # the session has expired so we need to log in again
            self.logger.debug("Login required!")

            username = self.credentials.get("identifier")
            password = self.credentials.get("password")

            # retry the original request with basic auth credentials
            return self._http_request(method, uri, body=body, params=params, files=files, auth=(username, password))
        elif resp.status_code >= 500:
            self.logger.error("A server error has occurred. The response is: " + json.dumps(resp.json()))

        if auth is not None:
            # persist the jwt
            jwt = resp.headers.get("auth-token")
            self.demisto.setIntegrationContext({"JWT": jwt})

        return resp

    def _get_error_msg_from_response(self, resp):
        err_msg = resp.json().get("msg")
        if err_msg is None:
            err_msg = resp.text
        return err_msg

    def event_context_table_to_dict_list(self, event_context_table):
        # convert context from column format to row format for display
        num_rows = functools.reduce(
            lambda acc, col: len(col.get("values")) if len(col.get("values")) > acc else acc,
            event_context_table.get("columns"),
            0,
        )
        new_table_data: List[Dict[str, str]] = [{} for row in range(num_rows)]

        for column in event_context_table.get("columns"):
            # add the column to the table
            for row in range(num_rows):
                # check if the column has the row data
                if len(column.get("values")) - row > 0:
                    # insert column data
                    val = list(
                        map(
                            lambda d: str(list(d.values())[0]) if len(list(d.values())) > 0 else "",
                            column.get("values")[row].get("data"),
                        )
                    )
                    table_row = new_table_data[row]
                    column_name = column.get("name")
                    table_row[column_name] = ",".join(val)
                else:
                    # This column is missing data so just insert an empty string
                    new_table_data[row][column.get("name")] = ""

        return new_table_data

    def event_context_table_to_dict(self, event_context_table):
        table_data = {}
        for column in event_context_table.get("columns"):
            val = list(
                map(lambda d: str(list(d.values())[0]) if len(list(d.values())) > 0 else "", column.get("values")[0].get("data"))
            )
            table_data[column.get("name")] = ",".join(val)

        return table_data

    def event_context_table_contains_multi_columns(self, event_context_table):
        for column in event_context_table.get("columns"):
            if len(column.get("values")) > 1:
                return True
        return False

    def create_markdown_link(self, link_text, url):
        return f"[{link_text}]({url})"

    def create_dome_markdown_link(self, link_text, alert_id):
        url = f"https://{self.host}/alerts/irondome?filter=alertId%3D%3D{alert_id}"
        return f"[{link_text}]({url})"

    """MAIN FUNCTIONS"""

    def fetch_dome_incidents(self, dome_categories=None, dome_limit=200):
        self.logger.debug("Fetching Dome incidents...")
        res = []
        if dome_categories is not None:
            dome_cats = ["DNC_" + str(cat).replace(" ", "_").upper() for cat in dome_categories]
        else:
            dome_cats = []

        req_body = json.dumps({"limit": dome_limit})

        resp = self._http_request("POST", "/GetDomeNotifications", body=req_body)
        if resp.ok:
            # Filter notifications
            notifs = resp.json()
            self.logger.debug("json response is: " + json.dumps(resp.json()))
            for n in notifs["dome_notifications"]:
                if n["category"] not in dome_cats:
                    n["type"] = "dome"
                    notif = {
                        "name": str(n["category"]) + " IronDome Notification",
                        "details": "Received a {} IronDome Notification at {} from communities {}.".format(
                            n["category"], str(datetime.now()), n["dome_tags"]
                        ),
                        "occurred": n["created"],
                        "rawJSON": json.dumps(n),
                    }
                    res.append(notif)
        else:
            raise Exception("Fetch for DomeNotifications failed. Status code was " + str(resp.status_code))

        self.logger.debug("{} Dome incident(s) fetched".format(len(res)))
        return res

    def fetch_alert_incidents(
        self,
        alert_categories=None,
        alert_subcategories=None,
        alert_severity_lower=None,
        alert_severity_upper=None,
        alert_limit=200,
        alert_actions=None,
    ):
        self.logger.debug("Fetching Alert incidents...")
        res = []

        if alert_categories is not None:
            alert_cats = [str(cat).replace(" ", "_").upper() for cat in alert_categories]
        else:
            alert_cats = []

        if alert_subcategories is not None:
            asc = alert_subcategories.split(",")
            alert_subcats = [str(subcat).replace(" ", "_").upper() for subcat in asc]
        else:
            alert_subcats = []

        if alert_actions is None or len(alert_actions) == 0:
            alert_actions_to_ingest = ["ANA_ALERT_CREATED"]
        else:
            alert_actions_to_ingest = ["ANA_" + str(alert_action).replace(" ", "_").upper() for alert_action in alert_actions]

        alert_sev_lower = int(alert_severity_lower) if alert_severity_lower is not None else 0
        alert_sev_upper = int(alert_severity_upper) if alert_severity_upper is not None else 1000

        req_body = json.dumps({"limit": alert_limit})

        resp = self._http_request("POST", "/GetAlertNotifications", body=req_body)
        if resp.ok:
            # Filter notifications
            notifs = resp.json()
            self.logger.debug("json response is: " + json.dumps(resp.json()))
            for alert_notification in notifs["alert_notifications"]:
                if alert_notification["alert"]:
                    alert = alert_notification["alert"]
                    action = alert_notification["alert_action"]
                    if (
                        alert["category"] not in alert_cats
                        and alert["sub_category"] not in alert_subcats
                        and alert_sev_lower <= int(alert["severity"]) <= alert_sev_upper
                        and action in alert_actions_to_ingest
                    ):
                        alert["type"] = "alert"
                        notif = {
                            "name": str(alert_notification["alert_action"]) + " Alert Notification",
                            "details": "Received a {} Alert Notification at {}.".format(
                                alert_notification["alert_action"], str(datetime.now())
                            ),
                            "occurred": alert["updated"],
                            "rawJSON": json.dumps(alert),
                        }
                        res.append(notif)
        else:
            raise Exception("Fetch for AlertNotifications failed. Status code was " + str(resp.status_code))

        self.logger.debug("{} Alert incident(s) fetched".format(len(res)))
        return res

    def fetch_event_incidents(
        self,
        event_categories=None,
        event_subcategories=None,
        event_severity_lower=None,
        event_severity_upper=None,
        event_limit=200,
        event_actions=None,
    ):
        self.logger.debug("Fetching Event incidents...")
        res = []

        if event_categories is not None:
            event_cats = [str(cat).replace(" ", "_").upper() for cat in event_categories]
        else:
            event_cats = []

        if event_subcategories is not None:
            esc = event_subcategories.split(",")
            event_subcats = [str(subcat).replace(" ", "_").upper() for subcat in esc]
        else:
            event_subcats = []

        if event_actions is None or len(event_actions) == 0:
            event_actions_to_ingest = ["ENA_EVENT_CREATED"]
        else:
            event_actions_to_ingest = ["ENA_" + str(event_action).replace(" ", "_").upper() for event_action in event_actions]

        event_sev_lower = int(event_severity_lower) if event_severity_lower is not None else 0
        event_sev_upper = int(event_severity_upper) if event_severity_upper is not None else 1000

        req_body = json.dumps({"limit": event_limit})

        resp = self._http_request("POST", "/GetEventNotifications", body=req_body)
        if resp.ok:
            # Filter notifications
            notifs = resp.json()
            self.logger.debug("json response is: " + json.dumps(resp.json()))
            for event_notification in notifs["event_notifications"]:
                if event_notification["event"]:
                    event = event_notification["event"]
                    action = event_notification["event_action"]
                    if (
                        event["category"] not in event_cats
                        and event["sub_category"] not in event_subcats
                        and event_sev_lower <= int(event["severity"]) <= event_sev_upper
                        and action in event_actions_to_ingest
                    ):
                        event["type"] = "event"
                        notif = {
                            "name": str(event_notification["event_action"]) + " Event Notification",
                            "details": "Received a {} Event Notification at {}.".format(
                                event_notification["event_action"], str(datetime.now())
                            ),
                            "occurred": event["updated"],
                            "rawJSON": json.dumps(event),
                        }
                        res.append(notif)
        else:
            raise Exception("Fetch for EventNotifications failed. Status code was " + str(resp.status_code))

        self.logger.debug("{} Event incident(s) fetched".format(len(res)))
        return res

    def test_module(self):
        self.logger.debug("Testing module...")
        username = self.credentials.get("identifier")
        password = self.credentials.get("password")
        resp = self._http_request("POST", "/Login", auth=(username, password))
        if resp.status_code == 200:
            self.logger.debug("Success!")
            return "ok"
        else:
            return "Test failed ({}): {}".format(str(resp.status_code), resp.json()["msg"])

    def update_analyst_ratings(
        self, alert_id, severity="SEVERITY_UNDECIDED", expectation="EXP_UNKNOWN", comments="", share_irondome=False
    ):
        self.logger.debug(
            "Submitting analyst rating: Alert ID={} Severity={} Expected={} Comments={} Share " "w/IronDome={}".format(
                alert_id, severity, expectation, comments, share_irondome
            )
        )

        req_body = {
            "alert_id": alert_id,
            "analyst_severity": "SEVERITY_" + severity.upper(),
            "analyst_expectation": "EXP_" + expectation.upper(),
            "comment": comments,
            "share_comment_with_irondome": share_irondome,
        }
        response = self._http_request("POST", "/RateAlert", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to rate alert ({}). The response failed with status code {}. The response was: " "{}".format(
                    alert_id, response.status_code, response.text
                )
            )
            raise HTTPException("Failed to rate alert {} ({}): {}".format(alert_id, response.status_code, err_msg))
        else:
            self.logger.debug("Successfully submitted rating for alert ({})".format(alert_id))
            return "Submitted analyst rating to IronDefense!"

    def add_comment_to_alert(self, alert_id, comment="", share_irondome=False):
        self.logger.debug(
            "Submitting comment: Alert ID={} Comment={} Share " "w/IronDome={}".format(alert_id, comment, share_irondome)
        )

        req_body = {"alert_id": alert_id, "comment": comment, "share_comment_with_irondome": share_irondome}
        response = self._http_request("POST", "/CommentOnAlert", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to add comment to alert ({}). The response failed with status code {}. The " "response was: {}".format(
                    alert_id, response.status_code, response.text
                )
            )
            raise HTTPException("Failed to add comment to alert {} ({}): {}".format(alert_id, response.status_code, err_msg))
        else:
            self.logger.debug("Successfully added comment to alert ({})".format(alert_id))
            return "Submitted comment to IronDefense!"

    def set_alert_status(self, alert_id, status="STATUS_NONE", comments="", share_irondome=False):
        self.logger.debug(
            "Submitting status: Alert ID={} Status={} Comments={} Share " "w/IronDome={}".format(
                alert_id, status, comments, share_irondome
            )
        )

        req_body = {
            "alert_id": alert_id,
            "status": "STATUS_" + status.upper().replace(" ", "_"),
            "comment": comments,
            "share_comment_with_irondome": share_irondome,
        }
        response = self._http_request("POST", "/SetAlertStatus", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to set status for alert ({}). The response failed with status code {}. The " "response was: {}".format(
                    alert_id, response.status_code, response.text
                )
            )
            raise HTTPException("Failed to set status for alert {} ({}): {}".format(alert_id, response.status_code, err_msg))
        else:
            self.logger.debug("Successfully submitted status for alert ({})".format(alert_id))
            return "Submitted status to IronDefense!"

    def report_observed_bad_activity(
        self,
        name,
        description="",
        ip="",
        domain="",
        activity_start_time="1970-01-01T00:00:00Z",
        activity_end_time="1970-01-01T00:00:00Z",
    ):
        self.logger.debug(
            "Submitting observed bad activity: Name={} Description={} IP={} Domain={} "
            "Activity Start Time={} Activity End Time={}".format(
                name, description, ip, domain, activity_start_time, activity_end_time
            )
        )

        req_body = {
            "name": name,
            "description": description,
            "ip": ip,
            "domain": domain,
            "activity_start_time": activity_start_time,
            "activity_end_time": activity_end_time,
        }
        response = self._http_request("POST", "/ReportObservedBadActivity", body=json.dumps(req_body))
        if response.ok:
            self.logger.debug("Successfully submitted observed bad activity for IP={} and Domain={}".format(ip, domain))
            return "Submitted observed bad activity to IronDefense!"
        else:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to submit observed bad activity for IP={} and Domain={}. The response failed with"
                " status code {}. The response was: {}".format(ip, domain, response.status_code, response.text)
            )
            raise HTTPException(
                "Failed to submit observed bad activity for IP={} and Domain={} ({}): {}".format(
                    ip, domain, response.status_code, err_msg
                )
            )

    def get_event(self, event_id):
        self.logger.debug("Retrieving Event: Event ID={}".format(event_id))

        req_body = {
            "event_id": event_id,
        }
        response = self._http_request("POST", "/GetEvent", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to retrieve event with ID ({}). The response failed with status code {}. The " "response was: {}".format(
                    event_id, response.status_code, response.text
                )
            )
            raise HTTPException("Failed to retrieve event with ID {} ({}): {}".format(event_id, response.status_code, err_msg))
        else:
            self.logger.debug("Successfully retrieved event ({})".format(event_id))
            return response.json()

    def get_events(self, alert_id, limit=None, offset=None):
        self.logger.debug("Retrieving Events: Alert ID={}, Limit={} Offset={}".format(alert_id, limit, offset))

        req_body = {"alert_id": alert_id}

        constraint = {}
        if limit is not None and limit != "":
            constraint["limit"] = int(limit)
        if offset is not None and offset != "":
            constraint["offset"] = int(offset)
        req_body["constraint"] = constraint

        response = self._http_request("POST", "/GetEvents", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to retrieve events with alert ID ({}). The response failed with status code {}. "
                "The response was: {}".format(alert_id, response.status_code, response.text)
            )
            raise HTTPException("Failed to retrieve event with ID {} ({}): {}".format(alert_id, response.status_code, err_msg))
        else:
            self.logger.debug("Successfully retrieved events for alert ({})".format(alert_id))
            events = response.json()
            return events

    def get_alerts(
        self,
        alert_id=None,
        category=None,
        sub_category=None,
        status=None,
        analyst_severity=None,
        analyst_expectation=None,
        min_severity=None,
        max_severity=None,
        min_created=None,
        max_created=None,
        min_updated=None,
        max_updated=None,
        min_first_event_created=None,
        max_first_event_created=None,
        min_last_event_created=None,
        max_last_event_created=None,
        min_first_event_start_time=None,
        max_first_event_start_time=None,
        min_last_event_end_time=None,
        max_last_event_end_time=None,
        analytic_version=None,
        limit=None,
        offset=None,
        sort=None,
    ):
        self.logger.debug(
            "Getting alerts: AlertID={} Category={} SubCategory={} Status={} AnalystSeverity={} "
            "AnalystExpectation={} MinSeverity={} MaxSeverity={} MinCreated={} MaxCreated= {} MinUpdated={}"
            "MaxUpdated={} MinFirstEventCreated={} MaxFirstEventCreated={} MinLastEventCreated={}"
            "MaxLastEventCreated={} MinFirstEventStartTime={} MaxFirstEventStartTime={} MinLastEventEndTime={}"
            "MaxLastEventEndTime={} AnalyticVersion={} "
            "Limit={} Offset={} sort={}".format(
                alert_id,
                category,
                sub_category,
                status,
                analyst_severity,
                analyst_expectation,
                min_severity,
                max_severity,
                min_created,
                max_created,
                min_updated,
                max_updated,
                min_first_event_created,
                max_first_event_created,
                min_last_event_created,
                max_last_event_created,
                min_first_event_start_time,
                max_first_event_start_time,
                min_last_event_end_time,
                max_last_event_end_time,
                analytic_version,
                limit,
                offset,
                sort,
            )
        )

        req_body = {}
        if alert_id:
            req_body["alert_id"] = alert_id.split(",")
        if category:
            req_body["category"] = [str(cat).replace(" ", "_").upper() for cat in category.split(",")]
        if sub_category:
            req_body["sub_category"] = [str(sub_cat).replace(" ", "_").upper() for sub_cat in sub_category.split(",")]
        if status:
            req_body["status"] = ["STATUS_" + str(stat).replace(" ", "_").upper() for stat in status.split(",")]
        if analyst_severity:
            req_body["analyst_severity"] = [
                "SEVERITY_" + str(aseverity).replace(" ", "_").upper() for aseverity in analyst_severity.split(",")
            ]
        if analyst_expectation:
            req_body["analyst_expectation"] = [
                "EXP_" + str(aexpectation).replace(" ", "_").upper() for aexpectation in analyst_expectation.split(",")
            ]
        if analytic_version:
            req_body["analytic_version"] = analytic_version.split(",")
        if sort:
            req_body["sort"] = sort
        if min_severity is not None and min_severity != "" and max_severity is not None and max_severity != "":
            req_body["severity"] = {"lower_bound": int(min_severity), "upper_bound": int(max_severity)}
        if min_created and max_created:
            req_body["created"] = {"start": min_created, "end": max_created}
        if min_updated and max_updated:
            req_body["updated"] = {"start": min_updated, "end": max_updated}
        if min_first_event_created and max_first_event_created:
            req_body["first_event_created"] = {"start": min_first_event_created, "end": max_first_event_created}
        if min_last_event_created and max_last_event_created:
            req_body["last_event_created"] = {"start": min_last_event_created, "end": max_last_event_created}
        if min_first_event_start_time and max_first_event_start_time:
            req_body["first_event_start_time"] = {"start": min_first_event_start_time, "end": max_first_event_start_time}
        if min_last_event_end_time and max_last_event_end_time:
            req_body["last_event_end_time"] = {"start": min_last_event_end_time, "end": max_last_event_end_time}
        constraint = {}
        if limit is not None and limit != "":
            constraint["limit"] = int(limit)
        if offset is not None and offset != "":
            constraint["offset"] = int(offset)
        req_body["constraint"] = constraint

        response = self._http_request("POST", "/GetAlerts", body=json.dumps(req_body))
        if response.ok:
            self.logger.debug("Successfully retrieved alerts")
            return response.json()
        else:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to retrieve alerts. The response failed with status code {}. The response was: {}".format(
                    response.status_code, err_msg
                )
            )
            raise HTTPException("Failed to retrieve alerts ({}): {}".format(response.status_code, err_msg))

    def get_alert_irondome_information(self, alert_id):
        self.logger.debug("Retrieving Alert IronDome Information: Alert ID={}".format(alert_id))

        req_body = {
            "alert_id": alert_id,
        }
        response = self._http_request("POST", "/GetAlertIronDomeInformation", body=json.dumps(req_body))
        if response.status_code != 200:
            err_msg = self._get_error_msg_from_response(response)
            self.logger.error(
                "Failed to retrieve IronDome information for alert with ID ({}). The response failed "
                "with status code {}. The response was: {}".format(alert_id, response.status_code, response.text)
            )
            raise HTTPException(
                "Failed to retrieve IronDome information for alert with ID {} ({}): {}".format(
                    alert_id, response.status_code, err_msg
                )
            )
        else:
            self.logger.debug("Successfully retrieved IronDome information for alert ({})".format(alert_id))
            dome_alert_info = response.json()
            return dome_alert_info


""" COMMANDS MANAGER / SWITCH PANEL """


def fetch_incidents_command():
    # IronDome Notification related params
    dome_categories = PARAMS.get("domeCategories", None)  # pylint: disable=E0601
    dome_limit = int(PARAMS.get("domeLimit", 200))
    disable_dome_notifs = not PARAMS.get("enableDomeNotifications", False)
    # Alert Notification related params
    alert_categories = PARAMS.get("alertCategories", None)
    alert_subcategories = PARAMS.get("alertSubCategories", None)
    alert_severity_lower = PARAMS.get("alertSeverityLower", None)
    alert_severity_upper = PARAMS.get("alertSeverityUpper", None)
    alert_limit = int(PARAMS.get("alertLimit", 200))
    alert_actions = PARAMS.get("alertActions", None)
    disable_alert_notifs = not PARAMS.get("enableAlertNotifications", True)
    # Event Notification related params
    event_categories = PARAMS.get("eventCategories", None)
    event_subcategories = PARAMS.get("eventSubCategories", None)
    event_severity_lower = PARAMS.get("eventSeverityLower", None)
    event_severity_upper = PARAMS.get("eventSeverityUpper", None)
    event_limit = int(PARAMS.get("eventLimit", 200))
    event_actions = PARAMS.get("eventActions", None)
    disable_event_notifs = not PARAMS.get("enableEventNotifications", False)

    incidents: list = []
    if disable_dome_notifs and disable_alert_notifs and disable_event_notifs:
        LOGGER.debug("Ingestion of all notifications (Dome, Alert, Event) is disabled, not fetching")  # pylint: disable=E0601
    else:
        if disable_dome_notifs:
            LOGGER.debug("Ingestion of Dome Notifications is disabled")
        else:
            incs = IRON_DEFENSE.fetch_dome_incidents(dome_categories, dome_limit)  # pylint: disable=E0601
            incidents.extend(incs)
            # If the limit was reached, poll again
            poll_count = 1
            while len(incs) == dome_limit and poll_count < 10:
                incs = IRON_DEFENSE.fetch_dome_incidents(dome_categories, dome_limit)
                incidents.extend(incs)
                poll_count += 1

        if disable_alert_notifs:
            LOGGER.debug("Ingestion of Alert Notifications is disabled")
        else:
            incs = IRON_DEFENSE.fetch_alert_incidents(
                alert_categories, alert_subcategories, alert_severity_lower, alert_severity_upper, alert_limit, alert_actions
            )
            incidents.extend(incs)
            # If the limit was reached, poll again
            poll_count = 1
            while len(incs) == alert_limit and poll_count < 10:
                incs = IRON_DEFENSE.fetch_alert_incidents(
                    alert_categories, alert_subcategories, alert_severity_lower, alert_severity_upper, alert_limit, alert_actions
                )
                incidents.extend(incs)
                poll_count += 1

        if disable_event_notifs:
            LOGGER.debug("Ingestion of Event Notifications is disabled")
        else:
            incs = IRON_DEFENSE.fetch_event_incidents(
                event_categories, event_subcategories, event_severity_lower, event_severity_upper, event_limit, event_actions
            )
            incidents.extend(incs)
            # If the limit was reached, poll again
            poll_count = 1
            while len(incs) == event_limit and poll_count < 10:
                incs = IRON_DEFENSE.fetch_event_incidents(
                    event_categories, event_subcategories, event_severity_lower, event_severity_upper, event_limit, event_actions
                )
                incidents.extend(incs)
                poll_count += 1

    demisto.incidents(incidents)


def test_module_command():
    results = IRON_DEFENSE.test_module()
    demisto.results(results)


def update_analyst_ratings_command():
    alert_id = demisto.getArg("alert_id")
    severity = demisto.getArg("severity")
    expectation = demisto.getArg("expectation")
    comments = demisto.getArg("comments")
    share_irondome_arg = demisto.getArg("share_comment_with_irondome")
    share_irondome = True if share_irondome_arg.lower() == "true" else False
    results = IRON_DEFENSE.update_analyst_ratings(
        alert_id, severity=severity, expectation=expectation, comments=comments, share_irondome=share_irondome
    )
    demisto.results(results)


def add_comment_to_alert_command():
    alert_id = demisto.getArg("alert_id")
    comment = demisto.getArg("comment")
    share_irondome_arg = demisto.getArg("share_comment_with_irondome")
    share_irondome = True if share_irondome_arg.lower() == "true" else False
    results = IRON_DEFENSE.add_comment_to_alert(alert_id, comment=comment, share_irondome=share_irondome)
    demisto.results(results)


def set_alert_status_command():
    alert_id = demisto.getArg("alert_id")
    status = demisto.getArg("status")
    comments = demisto.getArg("comments")
    share_irondome_arg = demisto.getArg("share_comment_with_irondome")
    share_irondome = True if share_irondome_arg.lower() == "true" else False
    results = IRON_DEFENSE.set_alert_status(alert_id, status=status, comments=comments, share_irondome=share_irondome)
    demisto.results(results)


def report_observed_bad_activity_command():
    name = demisto.getArg("name")
    description = demisto.getArg("description")
    ip = demisto.getArg("ip")
    domain = demisto.getArg("domain")
    activity_start_time = demisto.getArg("activity_start_time")
    activity_end_time = demisto.getArg("activity_end_time")
    results = IRON_DEFENSE.report_observed_bad_activity(
        name,
        description=description,
        ip=ip,
        domain=domain,
        activity_start_time=activity_start_time,
        activity_end_time=activity_end_time,
    )
    demisto.results(results)


def get_event_command():
    # get event data from IronAPI
    event_id = demisto.getArg("event_id")
    results = IRON_DEFENSE.get_event(event_id)

    # Output the event data
    event = results.get("event")
    vue_markdown_link = IRON_DEFENSE.create_markdown_link("Open in IronVue", event.get("vue_url"))
    event_readable_output = tableToMarkdown(
        f'IronDefense Event: {event.get("category")} -' f' {event.get("sub_category")}\n' f'{vue_markdown_link}', event
    )

    return_outputs(
        readable_output=event_readable_output,
        outputs={
            "IronDefense.Event(val.id == obj.id)": event,
        },
        raw_response=event,
    )

    # Output each context table
    context_tables = results.get("context")
    for table in context_tables:
        if IRON_DEFENSE.event_context_table_contains_multi_columns(table):
            output_table = IRON_DEFENSE.event_context_table_to_dict_list(table)
            headers = [*output_table[0]]
        else:
            output_table = IRON_DEFENSE.event_context_table_to_dict(table)
            headers = []

        return_outputs(
            readable_output=tableToMarkdown(f'Event Context: {table.get("name")}', output_table, headers=headers),
            outputs={
                "IronDefense.Event.Context(val.name == obj.name)": table,
            },
            raw_response=table,
        )


def get_events_command():
    alert_id = demisto.getArg("alert_id")
    limit = demisto.getArg("limit")
    offset = demisto.getArg("offset")

    results = IRON_DEFENSE.get_events(alert_id=alert_id, limit=limit, offset=offset)
    events = results.get("events")
    total_count = results.get("constraint").get("total")
    offset = results.get("constraint").get("offset")
    for i, event in enumerate(events):
        vue_markdown_link = IRON_DEFENSE.create_markdown_link("Open in IronVue", event.get("vue_url"))
        event_readable_output = tableToMarkdown(
            f"IronDefense Event {i + offset + 1}/{total_count}\n" f"{vue_markdown_link}", event
        )
        # Send each event
        return_outputs(
            readable_output=event_readable_output,
            outputs={
                "IronDefense.Event(val.id == obj.id)": event,
            },
            raw_response=event,
        )

    # Send constraints
    constraint = results.get("constraint")
    return_outputs(
        readable_output=tableToMarkdown("Query Constraints", constraint),
        outputs={
            "IronDefense.Query.GetEvents": constraint,
        },
        raw_response=constraint,
    )


def get_alerts_command():
    alert_id = demisto.getArg("alert_id")
    category = demisto.getArg("category")
    sub_category = demisto.getArg("sub_category")
    status = demisto.getArg("status")
    analyst_severity = demisto.getArg("analyst_severity")
    analyst_expectation = demisto.getArg("analyst_expectation")
    min_severity = demisto.getArg("min_severity")
    max_severity = demisto.getArg("max_severity")
    min_created = demisto.getArg("min_created")
    max_created = demisto.getArg("max_created")
    min_updated = demisto.getArg("min_updated")
    max_updated = demisto.getArg("max_updated")
    min_first_event_created = demisto.getArg("min_first_event_created")
    max_first_event_created = demisto.getArg("max_first_event_created")
    min_last_event_created = demisto.getArg("min_last_event_created")
    max_last_event_created = demisto.getArg("max_last_event_created")
    min_first_event_start_time = demisto.getArg("min_first_event_start_time")
    max_first_event_start_time = demisto.getArg("max_first_event_start_time")
    min_last_event_end_time = demisto.getArg("min_last_event_end_time")
    max_last_event_end_time = demisto.getArg("max_last_event_end_time")
    analytic_version = demisto.getArg("analytic_version")
    limit = demisto.getArg("limit")
    offset = demisto.getArg("offset")
    sort = demisto.getArg("sort")
    results = IRON_DEFENSE.get_alerts(
        alert_id=alert_id,
        category=category,
        sub_category=sub_category,
        status=status,
        analyst_severity=analyst_severity,
        analyst_expectation=analyst_expectation,
        min_severity=min_severity,
        max_severity=max_severity,
        min_created=min_created,
        max_created=max_created,
        min_updated=min_updated,
        max_updated=max_updated,
        min_first_event_created=min_first_event_created,
        max_first_event_created=max_first_event_created,
        min_last_event_created=min_last_event_created,
        max_last_event_created=max_last_event_created,
        min_first_event_start_time=min_first_event_start_time,
        max_first_event_start_time=max_first_event_start_time,
        min_last_event_end_time=min_last_event_end_time,
        max_last_event_end_time=max_last_event_end_time,
        analytic_version=analytic_version,
        limit=limit,
        offset=offset,
        sort=sort,
    )
    alerts = results.get("alerts")
    total_count = results.get("constraint").get("total")
    offset = results.get("constraint").get("offset")
    for i, alert in enumerate(alerts):
        # Send each alert
        vue_markdown_link = IRON_DEFENSE.create_markdown_link("Open in IronVue", alert.get("vue_url"))
        alert_readable_output = tableToMarkdown(
            f'IronDefense Alert {i + offset + 1}/{total_count}: {alert.get("category")} -'
            f' {alert.get("sub_category")}\n'
            f'{vue_markdown_link}',
            alert,
        )
        return_outputs(
            readable_output=alert_readable_output,
            outputs={
                "IronDefense.Alert(val.id == obj.id)": alert,
            },
            raw_response=alert,
        )

    # Send constraints
    constraint = results.get("constraint")
    return_outputs(
        readable_output=tableToMarkdown("Query Constraints", constraint),
        outputs={
            "IronDefense.Query.GetAlerts": constraint,
        },
        raw_response=constraint,
    )


def get_alert_irondome_information_command():
    alert_id = demisto.getArg("alert_id")
    results = IRON_DEFENSE.get_alert_irondome_information(alert_id)

    if (
        len(results.get("correlations")) == 0
        and len(results.get("correlation_participation")) == 0
        and len(results.get("community_comments")) == 0
        and len(results.get("dome_notifications")) == 0
    ):
        demisto.results(f"No correlations found for alert ID: {alert_id}")
        return

    # Output correlations
    correlations = results.get("correlations")
    for correlation in correlations:
        dome_tag = correlation.get("dome_tag")
        correlation_data = correlation.get("correlations")
        output = {"alert_id": alert_id, "correlation": correlation}
        ip_correlations = list(filter(lambda corr: corr.get("ip") is not None, correlation_data))
        domain_correlations = list(filter(lambda corr: corr.get("domain") is not None, correlation_data))
        behavior_correlations = list(filter(lambda corr: corr.get("behavior") is not None, correlation_data))

        if len(ip_correlations) != 0:
            return_outputs(
                readable_output=tableToMarkdown(
                    f'IronDome IP Correlations in "{dome_tag}"', ip_correlations, headers=[*ip_correlations[0]]
                ),
                outputs={"IronDome.Correlations(val.alert_id = obj.alert.id)": output},
                raw_response=correlation,
            )

        if len(domain_correlations) != 0:
            return_outputs(
                readable_output=tableToMarkdown(
                    f'IronDome Domain Correlations in "{dome_tag}"', domain_correlations, headers=[*domain_correlations[0]]
                ),
                outputs={"IronDome.Correlations(val.alert_id = obj.alert.id)": output},
                raw_response=correlation,
            )

        if len(behavior_correlations) != 0:
            return_outputs(
                readable_output=tableToMarkdown(
                    f'IronDome Behavior Correlations in "{dome_tag}"', behavior_correlations, headers=[*behavior_correlations[0]]
                ),
                outputs={"IronDome.Correlations(val.alert_id = obj.alert.id)": output},
                raw_response=correlation,
            )

    # Output correlation participation
    correlation_participation = results.get("correlation_participation")
    for participant in correlation_participation:
        dome_tag = participant.get("dome_tag")
        output = {"alert_id": alert_id, "correlation_participation": participant}

        table_data = []

        # append each correlation context to display in the table, if it exists
        behavior = participant.get("behavior")
        if behavior is not None:
            table_data.append(behavior)
        domain = participant.get("behavior")
        if domain is not None:
            table_data.append(domain)
        ip = participant.get("ip")
        if ip is not None:
            table_data.append(ip)

        # Send the participant info
        return_outputs(
            readable_output=tableToMarkdown(
                f'IronDome Correlation Participation in "{dome_tag}"', table_data, headers=[*table_data[0]]
            ),
            outputs={"IronDome.CorrelationParticipation(val.alert_id = obj.alert.id)": output},
            raw_response=participant,
        )

    # Output comments
    community_comments = results.get("community_comments")
    community_comments_output = {
        "alert_id": alert_id,
        "community_comments": community_comments,
    }
    if len(community_comments) > 0:
        return_outputs(
            readable_output=tableToMarkdown("IronDome Community Comments", community_comments, headers=[*community_comments[0]]),
            outputs={"IronDome.CommunityComments(val.alert_id = obj.alert.id)": community_comments_output},
            raw_response=community_comments,
        )

    # Output cognitive system score
    cognitive_system_score = results.get("cognitive_system_score")
    cognitive_system_score_output = {
        "alert_id": alert_id,
        "cognitive_system_score": cognitive_system_score,
    }
    return_outputs(
        readable_output=f"### Cognitive System Score: {cognitive_system_score}",
        outputs={"IronDome.CognitiveSystemScore(val.alert_id = obj.alert.id)": cognitive_system_score_output},
        raw_response=cognitive_system_score,
    )

    # Output dome notifications
    dome_notifications = results.get("dome_notifications")
    for notification in dome_notifications:
        category = notification.get("category")
        output = {"alert_id": alert_id, "dome_notification": notification}
        return_outputs(
            readable_output=tableToMarkdown(f"IronDome Notification: {category}", notification),
            outputs={"IronDome.Notification(val.alert_id = obj.alert.id)": output},
            raw_response=notification,
        )

    return_outputs(
        readable_output=IRON_DEFENSE.create_dome_markdown_link("Open IronDome information in IronVue", alert_id), outputs={}
    )


COMMANDS = {
    "test-module": test_module_command,
    "fetch-incidents": fetch_incidents_command,
    "irondefense-rate-alert": update_analyst_ratings_command,
    "irondefense-comment-alert": add_comment_to_alert_command,
    "irondefense-set-alert-status": set_alert_status_command,
    "irondefense-report-observed-bad-activity": report_observed_bad_activity_command,
    "irondefense-get-event": get_event_command,
    "irondefense-get-events-from-alert": get_events_command,
    "irondefense-get-alerts": get_alerts_command,
    "irondefense-get-alert-irondome-information": get_alert_irondome_information_command,
}
COOKIE_KEY = "user_sid"
LOG_PREFIX = "IronDefense Integration: "

"""EXECUTION"""

if __name__ == "builtins":
    try:
        # Globals
        PARAMS = demisto.params()
        CREDENTIALS = PARAMS.get("credentials")
        HOST = PARAMS.get("ironAPIHost", "localhost")
        PORT = PARAMS.get("ironAPIPort", 443)
        REQUEST_TIMEOUT = float(PARAMS.get("requestTimeout", 60))
        LOGGER = XsoarLogger(demisto, LOG_PREFIX)

        # initialize the IronDefense object
        IRON_DEFENSE = IronDefense(demisto, requests.Session(), HOST, PORT, CREDENTIALS, LOGGER, request_timeout=REQUEST_TIMEOUT)

        LOGGER.debug("Invoking integration with Command: " + demisto.command())
        if demisto.command() in COMMANDS.keys():
            COMMANDS[demisto.command()]()
        else:
            return_error("Command not found: " + demisto.command())

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(str(e))
