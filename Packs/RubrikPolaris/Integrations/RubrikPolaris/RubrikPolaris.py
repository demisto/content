import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import urllib3
import traceback
from typing import Tuple, List, Dict
from datetime import date, datetime
import dateparser
import re

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
# The time, in minutes, that we should check for new incidents
FETCH_TIME = 5
OPERATION_NAME_PREFIX = "SdkCortexXsoar"

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the Rubrik Polaris API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.

    It inherits from BaseClient defined in CommonServer Python.
    """

    def get_api_token(self) -> str:
        # email is the customer facing version of the username
        # param
        username = demisto.params().get('email', False)
        password = demisto.params().get('password', False)

        auth_data = {
            "username": username,
            "password": password,
        }

        authentication_api = "/session"

        response = self._http_request(
            url_suffix=authentication_api,
            method='POST',
            json_data=auth_data
        )

        return response["access_token"]

    def gql_query(self, operation_name: str, query: str, variables: dict, isPagination: bool) -> dict:
        query_api = "/graphql"
        # When paginating the results we already have the session API token
        if isPagination is False:
            api_token = self.get_api_token()
            self._headers["Authorization"] = f"Bearer {api_token}"

        query_body = {
            "operationName": operation_name,
            "query": query,
            "variables": variables

        }

        response = self._http_request(
            url_suffix=query_api,
            method='POST',
            json_data=query_body
        )

        return response


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: RubrikPolaris client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    max_fetch = demisto.params().get('max_fetch')
    first_fetch = demisto.params().get('first_fetch')

    if max_fetch:

        try:
            max_fetch = int(max_fetch)
        except ValueError:
            return "The 'Fetch Limit' is not a valid integer. The default value is 50 with a maximum of 200."
        if max_fetch > 200:
            return "The 'Fetch Limit' can not be greater than 200."

    if first_fetch:
        try:
            last_run_obj = dateparser.parse(first_fetch, [DATE_TIME_FORMAT])
            if last_run_obj is None:
                raise ValueError
        except ValueError:
            return "We were unable to parse the First Fetch variable. Make sure the provided value follows the " \
                   "Relative Dates outlined at https://dateparser.readthedocs.io/en/latest/#relative-dates"
    try:
        client.get_api_token()
    except DemistoException as e:
        errorMessage = str(e)
        if 'Verify that the server URL parameter' in errorMessage:
            return "We were unable to connect to the provided Polaris Account. Verify it has been entered correctly."
        elif 'Unauthorized' in errorMessage:
            return "Incorrect email address or password."
        else:
            raise e
    return "ok"


def fetch_incidents(client: Client, max_fetch: int) -> Tuple[str, List[dict]]:
    # Returns an obj with the previous run in it.
    last_run = demisto.getLastRun().get('last_fetch', None)

    if last_run is None:
        # if the last run has not been set (i.e on the first run)
        # check to see if a first_fetch value has been provided. If it hasn't
        # return the current time
        first_fetch = demisto.params().get('first_fetch')
        last_run_obj = dateparser.parse(first_fetch, [DATE_TIME_FORMAT])
        last_run = last_run_obj.strftime(DATE_TIME_FORMAT)

        if last_run_obj is None:
            current_time = datetime.now()
            return current_time.strftime(DATE_TIME_FORMAT), []
    else:
        last_run_obj = (datetime.strptime(last_run, DATE_TIME_FORMAT))

    if last_run_obj > (datetime.now() - timedelta(minutes=FETCH_TIME)):
        # It has not been FETCH_TIME since the last fetch
        # return blank values and skip the fetch
        return "", []
    else:

        operation_name = f"{OPERATION_NAME_PREFIX}RadarEvents"

        query = """query %s($filters: ActivitySeriesFilterInput, $after: String) {
                    activitySeriesConnection(first: 20, filters: $filters, after: $after) {
                        edges {
                            node {
                                id
                                fid
                                activitySeriesId
                                lastUpdated
                                lastActivityType
                                lastActivityStatus
                                objectId
                                objectName
                                objectType
                                severity
                                progress
                                cluster {
                                    id
                                    name
                                }
                                activityConnection {
                                    nodes {
                                        id
                                        message
                                        severity
                                        time
                                    }
                                }
                            }
                        }
                        pageInfo {
                            endCursor
                            hasNextPage
                        }
                    }
                    featureFlag(entityType: ACCOUNT, flagName: DataClassificationEnabled) {
                        name
                        variant
                    }
                }""" % operation_name

        variables = {
            "filters": {
                "lastActivityType": [
                    "Anomaly"
                ],
                "lastUpdated_gt": last_run
            },
        }

        radar_events = client.gql_query(operation_name, query, variables, False)

        if radar_events['data']["activitySeriesConnection"]['pageInfo']['hasNextPage'] is True:
            pagination_results = []

            variables["after"] = radar_events['data']["activitySeriesConnection"]["pageInfo"]['endCursor']

            while True:
                radar_events_pagination = client.gql_query(operation_name, query, variables, True)

                for data in radar_events_pagination["data"]["activitySeriesConnection"]["edges"]:
                    pagination_results.append(data)
                if radar_events_pagination['data']["activitySeriesConnection"]['pageInfo']['hasNextPage'] is False:
                    break

                variables["after"] = radar_events_pagination['data']["activitySeriesConnection"]["pageInfo"][
                    'endCursor']

            for node in pagination_results:
                radar_events['data']["activitySeriesConnection"]["edges"].append(node)

        # Placeholder to save all anamaly events detected
        incidents = []
        current_time = datetime.now()

        for event in radar_events["data"]["activitySeriesConnection"]["edges"]:

            # Extra data from the Rubrik API event and save in a XSoar friendly format
            process_incident = {}  # mypy: ignore
            process_incident["incidentClassification"] = "RubrikRadar"
            process_incident["message"] = []  # type: ignore
            process_incident["severity"] = 0  # type: ignore

            for key, value in event["node"].items():
                # Simplify the message data
                if key == "activityConnection":
                    for m in value["nodes"]:

                        # Convert time to friendly display format
                        display_time = datetime.strptime(m["time"], "%Y-%m-%dT%H:%M:%S.%fZ")
                        display_time = display_time.strftime('%b %d, %Y at %I:%M:%S %p')

                        process_incident["message"].append({  # type: ignore
                            "message": m["message"],
                            "id": m["id"],
                            "severity": m["severity"],
                            "time": display_time
                        })

                        # Check if message includes the File Change attributes
                        file_changes_match = re.search(
                            r'File Change: ([0-9]+) Added, ([0-9]+) Modified, ([0-9]+) Removed', m["message"]
                        )
                        if file_changes_match is not None:
                            try:
                                process_incident["radar_files_added"] = file_changes_match.group(1)
                                process_incident["radar_files_modified"] = file_changes_match.group(2)
                                process_incident["radar_files_deleted"] = file_changes_match.group(3)

                            except KeyError:
                                demisto.info("Error Parsing Radar Anomaly File Change attributes")

                else:
                    process_incident[key] = value

            # Map Severity Level

            if event["node"]["severity"] == "Critical":

                if demisto.params().get('radar_critical_severity_mapping') is None:
                    critical_mapping = 'XSOAR LOW'
                else:
                    critical_mapping = demisto.params().get('radar_critical_severity_mapping')

                process_incident["severity"] = convert_to_demisto_severity(critical_mapping)  # type: ignore

            elif event["node"]["severity"] == "Warning":

                if demisto.params().get('radar_warning_severity_mapping') is None:
                    warning_mapping = 'XSOAR LOW'
                else:
                    warning_mapping = demisto.params().get('radar_warning_severity_mapping')

                process_incident["severity"] = convert_to_demisto_severity(warning_mapping)  # type: ignore
            else:
                process_incident["severity"] = IncidentSeverity.LOW  # type: ignore

            # Check to see if Sonar is enabled and assign context label

            if radar_events["data"]["featureFlag"]["variant"] == "true":
                process_incident["data_classification_enabled"] = True  # type: ignore
            else:
                process_incident["data_classification_enabled"] = False  # type: ignore

            incidents.append({
                "name": f'Rubrik Radar Anomaly - {process_incident["objectName"]}',
                "occurred": process_incident["lastUpdated"],
                "rawJSON": json.dumps(process_incident),
                "severity": process_incident["severity"]
            })

        if len(incidents) > max_fetch:
            return current_time.strftime(DATE_TIME_FORMAT), incidents[:max_fetch]

        return current_time.strftime(DATE_TIME_FORMAT), incidents


def rubrik_radar_analysis_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident().get("CustomFields")

    # activitySeriesId is an optional value for the command. When not set,
    # look up the value in the incident custom fields
    activitySeriesId = args.get('activitySeriesId', None)
    if not activitySeriesId:
        try:
            activitySeriesId = incident.get("rubrikpolarisactivityseriesid")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The activitySeriesId value is required. Either manually provide or run this "
                        "command in a 'Rubrik Radar Anomaly' incident where it will automatically looked "
                        "up using the incident context.",
                error=e)

    operation_name = f"{OPERATION_NAME_PREFIX}AnomalyEventSeriesDetailsQuery"

    query = """query %s($activitySeriesId: UUID!, $clusterUuid: UUID!) {
                    activitySeries(activitySeriesId: $activitySeriesId, clusterUuid: $clusterUuid) {
                        activityConnection {
                            nodes {
                                    id
                                    message
                                    time
                            }
                        }
                        progress
                        lastUpdated
                        lastActivityStatus
                    }
                }
                    """ % operation_name

    variables = {
        "clusterUuid": incident.get("rubrikpolariscdmclusterid"),
        "activitySeriesId": activitySeriesId
    }

    radar_update_events = client.gql_query(operation_name, query, variables, False)

    context = {
        "ClusterID": incident.get("rubrikpolariscdmclusterid"),
        "ActivitySeriesId": activitySeriesId,
        "Message": radar_update_events["data"]["activitySeries"]["activityConnection"]["nodes"]
    }

    if radar_update_events["data"]["activitySeries"]["lastActivityStatus"] == "Success":
        context["EventComplete"] = "True"
    else:
        context["EventComplete"] = "False"

    return CommandResults(
        outputs_prefix='Rubrik.Radar',
        outputs_key_field='ActivitySeriesId',
        outputs=context
    )


def rubrik_sonar_sensitive_hits_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident().get("CustomFields")

    # objectName is an optional value for the command. When not set,
    # look up the value in the incident custom fields
    objectName = args.get('objectName', None)
    if not objectName:
        try:
            objectName = incident.get("rubrikpolarisobjectname")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The objectName value is required. Either manually provide or run this command"
                        " in a 'Rubrik Radar Anomaly' incident where it will automatically looked up "
                        "using the incident context.",
                error=e)

    searchTimePeriod = args.get('searchTimePeriod', None)
    if not searchTimePeriod:
        searchTimePeriod = 7
    else:
        # Convert the provided argument into an int
        searchTimePeriod = int(searchTimePeriod)
    object_details = {}

    operation_name_object_list = f"{OPERATION_NAME_PREFIX}ObjectsListQuery"

    object_details_query = """query %s($day: String!, $timezone: String!) {
                            policyObjConnection(day: $day, timezone: $timezone) {
                                edges {
                                    node {
                                        snapshotFid
                                        snapshotTimestamp
                                        objectStatus {
                                            latestSnapshotResult {
                                                snapshotTime
                                                snapshotFid
                                            }
                                        }
                                        snappable {
                                            name
                                            id

                                        }
                                    }
                                }
                            }
                        }
                    """ % operation_name_object_list

    # Get todays current day
    search_day = date.today()

    object_details_variable = {
        "day": search_day.strftime("%Y-%m-%d"),
        "timezone": "UTC"
    }

    sonar_object_detail = client.gql_query(operation_name_object_list, object_details_query, object_details_variable,
                                           False)

    # Check the sonar_object_detail for the provided object name and
    # store its details for subsequent API call
    for sonar_object in sonar_object_detail["data"]["policyObjConnection"]["edges"]:

        if sonar_object["node"]["snappable"]["name"] == objectName:
            object_details["id"] = sonar_object["node"]["snappable"]["id"]
            object_details["snapshot_time"] = sonar_object["node"]["objectStatus"]["latestSnapshotResult"][
                "snapshotTime"]
            object_details["snapshot_fid"] = sonar_object["node"]["objectStatus"]["latestSnapshotResult"]["snapshotFid"]

    # If the provided object does not have any sensitive hits for today, look for
    # results from the searchTimePeriod. If results are found, stop the search
    if len(object_details) == 0:
        for d in range(1, searchTimePeriod):
            past_search_day = search_day - timedelta(days=d)

            object_details_variable["day"] = past_search_day.strftime("%Y-%m-%d")

            sonar_object_detail = client.gql_query(
                operation_name_object_list, object_details_query, object_details_variable, False)

            for sonar_object in sonar_object_detail["data"]["policyObjConnection"]["edges"]:
                if sonar_object["node"]["snappable"]["name"] is objectName:
                    object_details["id"] = sonar_object["node"]["snappable"]["id"]
                    object_details["snapshot_time"] = sonar_object["node"]["objectStatus"]["latestSnapshotResult"][
                        "snapshotTime"]
                    object_details["snapshot_fid"] = sonar_object["node"]["objectStatus"]["latestSnapshotResult"][
                        "snapshotFid"]

            if len(object_details) == 1:
                break

    # If no results were found from the searchTimePeriod return blank
    # context data to avoid an error
    if len(object_details) == 0:
        return CommandResults(
            outputs_prefix='Rubrik.Sonar',
            outputs_key_field='Id',
            outputs={}
        )

    operation_name_object_detail = f"{OPERATION_NAME_PREFIX}ObjectDetailQuery"

    sensitive_hits_query = """query %s($snappableFid: String!, $snapshotFid: String!) {
                policyObj(snappableFid: $snappableFid, snapshotFid: $snapshotFid) {
                    id
                    rootFileResult {
                        hits {
                            totalHits
                    }
                    analyzerGroupResults {
                        analyzerGroup {
                            name
                        }
                        analyzerResults {
                            hits {
                                totalHits
                            }
                            analyzer {
                                name
                            }
                        }
                            hits {
                            totalHits
                        }
                    }
                    filesWithHits {
                        totalHits
                    }
                    openAccessFiles {
                        totalHits
                    }
                    openAccessFolders {
                        totalHits
                    }
                    openAccessFilesWithHits {
                        totalHits
                    }
                    staleFiles {
                        totalHits
                    }
                    staleFilesWithHits {
                        totalHits
                    }
                    openAccessStaleFiles {
                        totalHits
                    }
                    }
                }
            }
                """ % operation_name_object_detail

    sensitive_hits_variables = {
        "snappableFid": object_details["id"],
        "snapshotFid": object_details["snapshot_fid"]
    }

    # spanId:uoH6A/2xDM8= traceId:/64k4L3xe74eS9LyVe3rjg==]] locations:[map[column:17 line:2]]
    sensitive_hits = client.gql_query(operation_name_object_detail, sensitive_hits_query, sensitive_hits_variables,
                                      False)

    policy_hits = {}  # type: ignore
    for h in sensitive_hits["data"]["policyObj"]["rootFileResult"]["analyzerGroupResults"]:
        policy_name = h["analyzerGroup"]["name"]
        policy_hits[policy_name] = {}

        for a in h["analyzerResults"]:
            analzer_name = a["analyzer"]["name"]
            analyzer_hits = str(a["hits"]["totalHits"])
            policy_hits[policy_name][analzer_name] = analyzer_hits

    context = {}
    root = sensitive_hits["data"]["policyObj"]["rootFileResult"]
    context["id"] = sensitive_hits["data"]["policyObj"]["id"]
    context["totalHits"] = root["hits"]["totalHits"]
    context["policy_hits"] = policy_hits
    context["filesWithHits"] = root["filesWithHits"]["totalHits"]
    context["openAccessFiles"] = root["openAccessFiles"]["totalHits"]
    context["openAccessFolders"] = root["openAccessFolders"]["totalHits"]
    context["openAccessFilesWithHits"] = root["openAccessFilesWithHits"]["totalHits"]
    context["staleFiles"] = root["staleFiles"]["totalHits"]
    context["staleFilesWithHits"] = root["staleFilesWithHits"]["totalHits"]
    context["openAccessStaleFiles"] = root["openAccessStaleFiles"]["totalHits"]

    return CommandResults(
        outputs_prefix='Rubrik.Sonar',
        outputs_key_field='Id',
        outputs=context
    )


def rubrik_cdm_cluster_location_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident().get("CustomFields")

    # clusterId is an optional value for the command. When not set,
    # look up the value in the incident custom fields
    clusterId = args.get('clusterId', None)
    if not clusterId:
        try:
            clusterId = incident.get("rubrikcdmclusterid")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The objectName value is required. Either manually provide or run this command"
                        " in a 'Rubrik Radar Anomaly' incident where it will automatically looked up "
                        "using the incident context.",
                error=e)

    if not clusterId:
        try:
            clusterId = incident.get("rubrikpolariscdmclusterid")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The objectName value is required. Either manually provide or run this command"
                        " in a 'Rubrik Radar Anomaly' incident where it will automatically looked up "
                        "using the incident context.",
                error=e)

    operation_name_object_list = f"{OPERATION_NAME_PREFIX}CDMClusterLocationQuery"

    cdm_location_query = """query %s($filter: ClusterFilterInput) {
                                clusterConnection(filter: $filter) {
                                    nodes{
                                        geoLocation{
                                            address
                                        }
                                    }
                                }
                            }
                    """ % operation_name_object_list

    cdm_location_variable = {
        "filter": {
            "id": [clusterId]
        }
    }

    cdm_location_detail = client.gql_query(operation_name_object_list, cdm_location_query, cdm_location_variable,
                                           False)

    context = {}

    try:
        context["location"] = cdm_location_detail["data"]["clusterConnection"]["nodes"][0]["geoLocation"]["address"]

    except KeyError:
        # Return blank context if key error
        return CommandResults(
            outputs_prefix='Rubrik.CDM.Cluster',
            outputs_key_field='Location',
            outputs={}
        )

    return CommandResults(
        outputs_prefix='Rubrik.CDM.Cluster',
        outputs_key_field='Location',
        outputs=context
    )


def rubrik_cdm_cluster_connection_state_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident().get("CustomFields")

    # clusterId is an optional value for the command. When not set,
    # look up the value in the incident custom fields
    clusterId = args.get('clusterId', None)
    if not clusterId:
        try:
            clusterId = incident.get("rubrikcdmclusterid")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The objectName value is required. Either manually provide or run this command"
                        " in a 'Rubrik Radar Anomaly' incident where it will automatically looked up "
                        "using the incident context.",
                error=e)

    if not clusterId:
        try:
            clusterId = incident.get("rubrikpolariscdmclusterid")
        except AttributeError as e:
            # if still not found return an error message about it being
            # required
            return_error(
                message="The objectName value is required. Either manually provide or run this command"
                        " in a 'Rubrik Radar Anomaly' incident where it will automatically looked up "
                        "using the incident context.",
                error=e)

    operation_name_object_list = f"{OPERATION_NAME_PREFIX}CDMClusterConnectionStateQuery"

    cdm_connection_query = """query %s($filter: ClusterFilterInput) {
                                clusterConnection(filter: $filter) {
                                    nodes {
                                        state {
                                            connectedState
                                        }
                                    }
                                }
                            }
                    """ % operation_name_object_list

    cdm_connection_variable = {
        "filter": {
            "id": [clusterId]
        }
    }

    cdm_connection_detail = client.gql_query(operation_name_object_list, cdm_connection_query, cdm_connection_variable, False)

    context = {}

    try:
        context["ConnectionState"] = cdm_connection_detail["data"]["clusterConnection"]["nodes"][0]["state"]["connectedState"]

    except KeyError:
        # Return blank context if key error
        return CommandResults(
            outputs_prefix='Rubrik.CDM.Cluster',
            outputs_key_field='ConnectionState',
            outputs={}
        )

    return CommandResults(
        outputs_prefix='Rubrik.CDM.Cluster',
        outputs_key_field='ConnectionState',
        outputs=context
    )


def convert_to_demisto_severity(severity='XSOAR LOW') -> int:
    """Maps the severity from the Rubrik Radar event to the user specified XSOAR severity level."""
    demisto.info("SEVERITY TO CONVERT IS: " + severity)
    return {
        'XSOAR LOW': IncidentSeverity.LOW,
        'XSOAR MEDIUM': IncidentSeverity.MEDIUM,
        'XSOAR HIGH': IncidentSeverity.HIGH,
        'XSOAR CRITICAL': IncidentSeverity.CRITICAL
    }[severity]


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    polaris_account = demisto.params().get('polaris_account', False)
    polaris_domain_name = "my.rubrik.com"
    polaris_base_url = f"https://{polaris_account}.{polaris_domain_name}/api"

    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'Accept': 'application/json, text/plain'
    }

    client = Client(
        base_url=polaris_base_url,
        headers=headers,
        verify=False
    )

    max_fetch = demisto.params().get('max_fetch')
    max_fetch = int(demisto.params().get('max_fetch')) if (max_fetch and max_fetch.isdigit()) else 50
    max_fetch = max(min(200, max_fetch), 1)

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            current_time, incidents = fetch_incidents(client, max_fetch)
            # A blank current_time is returned when it has not been 5 minutes
            # since the last fetch
            if current_time != "":
                demisto.setLastRun({
                    'last_fetch': current_time
                })

            demisto.incidents(incidents)

        elif demisto.command() == 'rubrik-radar-analysis-status':
            return_results(rubrik_radar_analysis_status_command(client, demisto.args()))
        elif demisto.command() == 'rubrik-sonar-sensitive-hits':
            return_results(rubrik_sonar_sensitive_hits_command(client, demisto.args()))
        elif demisto.command() == 'rubrik-cdm-cluster-location':
            return_results(rubrik_cdm_cluster_location_command(client, demisto.args()))
        elif demisto.command() == 'rubrik-cdm-cluster-connection-state':
            return_results(rubrik_cdm_cluster_connection_state_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
