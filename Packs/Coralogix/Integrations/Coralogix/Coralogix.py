import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# TODO: Add description to the integration in <root>/Packs/Coralogix/Integrations/Coralogix/Coralogix_description.md
from datetime import datetime, UTC

from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import urllib3
import dateutil.parser
# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

''' SUPPLEMENTAL FUNCTIONS '''


def strip_or_empty(o):
    try:
        if o is not None:
            return o.strip()
        else:
            o = ''
    except AttributeError:
        o = ''

    return o


def flatten_json(y):
    """
    This supplemental method flattens a JSON by renaming subfields using dots as delimiters between levels

    Args:
        y - the JSON to flatten

    Returns:
        A flattened JSON string
    """
    out = {}

    def flatten(x, name=''):

        # If the Nested key-value
        # pair is of dict type
        if type(x) is dict:

            for a in x:
                flatten(x[a], name + a + '.')

            # If the Nested key-value
        # pair is of list type
        elif type(x) is list:

            i = 0

            for a in x:
                flatten(a, name + str(i) + '.')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def elastic_output_as_table(raw_elastic_json_obj):
    """
    This supplemental method converts an Elasticsearch output JSON object to a Demisto table

    Args:
         raw_elastic_json_obj - The raw Elasticsearch output as received from the Elasticsearch API
         filter_out_columns - A strings array which contains the list of columns to remove from the output
    Returns:
         An object that represents a Demisto table with the data from the Elasticsearch output
    """

    # fill in the table and the raw contents objects
    table = []
    for raw_row in raw_elastic_json_obj["hits"]["hits"]:
        raw_row_flattened = flatten_json(raw_row["_source"])
        table.append(raw_row_flattened)

    return table


''' COMMANDS '''


def coralogix_search_command(
        cgx_private_key,
        cgx_endpoint_url,
        query,
        columns_to_include_in_human_readable,
        application_name,
        subsystem_name,
        severity,
        since_timestamp=None,
        to_timestamp="now",
        max_items_to_retrieve=-1):
    """
    This method handles the cgx_search command which allows the user to search for data on a Coralogix account

    Args:
        cgx_private_key - String, Coralogix Private Key (From the integration's settings page)
        cgx_endpoint_url - Coralogix ES-API base URL (From the integration's settings page)
        query - The Lucene query to send to Coralogix
        columns_to_include_in_human_readable - Strings Array, Columns to include in the human readable output
        application_name - String, The Coralogix application name to look for (optional)
        subsystem_name - String, The Coralogix subsystem name to look for (optional)
        severity - String, The Coralogix severity to look for (optional)
    Returns:
        A demisto CommandResults object
    """
    http = urllib3.PoolManager()
    pre_query = ""
    if len(strip_or_empty(application_name)) > 0:
        pre_query = 'coralogix.metadata.applicationName:"' + application_name + '"'
    if len(strip_or_empty(pre_query)) > 0:
        pre_query = pre_query + ' AND '
    if len(strip_or_empty(subsystem_name)) > 0:
        pre_query = pre_query + 'coralogix.metadata.subsystemName:"' + subsystem_name + '"'
    if len(strip_or_empty(pre_query)) > 0:
        pre_query = pre_query + ' AND '
    if len(strip_or_empty(severity)) > 0:
        pre_query = pre_query + 'coralogix.severity_str:"' + severity + '"'
    if len(strip_or_empty(pre_query)) > 0:
        query = '(' + pre_query + ') AND (' + query + ')'

    request_data = {
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": query
                        }
                    }
                ]
            }
        }
    }
    if since_timestamp is not None:
        request_data["query"]["bool"]["must"].append({
            "range": {
                "coralogix.timestamp": {
                    "gt": since_timestamp,
                    "lt": to_timestamp
                }
            }
        })
    if since_timestamp is None and to_timestamp != "now":
        raise ValueError("to_timestamp can only be set together with since_timestamp")

    if max_items_to_retrieve > 0:
        request_data["size"] = max_items_to_retrieve
    encoded_data = json.dumps(request_data).encode('utf-8')
    demisto.info('Calling `' + cgx_endpoint_url + '` with these args ' + json.dumps(request_data) + ' ...')
    r = http.request(
        'POST',
        cgx_endpoint_url,
        body=encoded_data,
        headers={
            "token": cgx_private_key,
            "Content-type": "application/json"
        })
    results_raw = json.loads(r.data.decode('utf-8'))
    if 'hits' in results_raw and 'hits' in results_raw['hits']:
        formatted_data = elastic_output_as_table(raw_elastic_json_obj=results_raw)
        return CommandResults(
            raw_response=results_raw,
            readable_output=tableToMarkdown(
                'Coralogix Search Results',
                formatted_data,
                columns_to_include_in_human_readable,
                removeNull=True),
            outputs_key_field="_id",
            outputs_prefix='Coralogix.SearchResults',
            outputs=results_raw['hits']['hits']
        )
    else:
        return CommandResults(
            raw_response=results_raw,
            readable_output=tableToMarkdown(
                'Coralogix Search Results',
                [],
                columns_to_include_in_human_readable,
                removeNull=True),
            outputs_key_field="_id",
            outputs_prefix='Coralogix.SearchResults',
            outputs=[]
        )


def coralogix_tag_command(
        private_key,
        coralogix_url,
        application_name,
        subsystem_name,
        tag_name,
        tag_timestamp="",
        tag_icon_url=""):
    """
    This method handles the cgx_tag command which allows the user to tag a certain timestamp on Coralogix (for example to mark
        the time at which an incident has occurred)

    Args:
        private_key - String, Coralogix Private Key (From the integration's settings page)
        coralogix_url - String, Coralogix Web-API base URL (From the integration's settings page)
        application_name - String, The application name that will be associated with the tag (Would probably be
                       something like 'Demisto')
        subsystem_name - String, The subsystem name that will be associated with the tag (Would probably be
                       something like 'Demisto')
        tag_name - String, The name of the tag that will be created
        tag_timestamp - String, The date at which to put the tag in Coralogix. (Optional, if not set,
                       the current time will be used by Coralogix)
        tag_icon_url - String, A URL for an image that will be used in the tag. Cannot exceed 50KB. (Optional, if not set,
                       Coralogix will automatically choose an image)
    Returns:
        The raw response from Coralogix WebAPI. If it is JSON parsable it will return it as an object, otherwise - as a string.
    """
    query_string_params = {
        'key': private_key,
        'application': application_name,
        'subsystem': subsystem_name,
        'name': tag_name
    }
    if len(tag_timestamp) > 0:
        query_string_params["timestamp"] = tag_timestamp
    if len(tag_icon_url) > 0:
        query_string_params["iconUrl"] = tag_icon_url

    demisto.info('Calling `' + coralogix_url + '` using GET with these args ' + json.dumps(query_string_params) + ' ...')
    response = requests.post(coralogix_url, params=query_string_params)
    try:
        results_obj = json.loads(response.text)
        if "tag_status" in results_obj and results_obj["tag_status"] == "SUCCESSFUL":
            return CommandResults(
                raw_response=results_obj,
                outputs_prefix='Coralogix.TagResults',
                readable_output='Tag added successfully',
                outputs=['Tag was successfully created at ' + tag_timestamp + ' under the name ' + tag_name]
            )
        else:
            return CommandResults(
                raw_response=results_obj,
                outputs_prefix='Coralogix.TagResults',
                readable_output='Failed to add the requested tag',
                outputs=['Failed to tag the following timestamp ' + tag_timestamp + ' under the name ' + tag_name]
            )

    except json.JSONDecodeError:
        raise ValueError('Failed to tag the following timestamp ' + tag_timestamp + ' under the name ' + tag_name
                         + '. This is the raw response:\n' + response.text)


def test_module(cgx_private_key, cgx_endpoint_url):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        cgx_private_key: Coralogix Private Key
        cgx_endpoint_url: Coralogix Cluster Base URL for the Coralogix ES-API

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    request_data = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "coralogix.timestamp": {
                                "gte": "now-15m",
                                "lt": "now"
                            }
                        }
                    }
                ]
            }
        }
    }

    try:
        encoded_data = json.dumps(request_data).encode('utf-8')
        demisto.info('Calling `' + cgx_endpoint_url + '` with these args ' + json.dumps(request_data) + ' ...')
        http = urllib3.PoolManager()
        r = http.request(
            'GET',
            cgx_endpoint_url,
            body=encoded_data,
            headers={
                "token": cgx_private_key,
                "Content-type": "application/json"
            })
        results_raw = json.loads(r.data.decode('utf-8'))
    except Exception as ex:
        return 'Test failed (' + type(ex).__name__ + ')'

    if results_raw is not None and 'hits' in results_raw:
        return 'ok'
    else:
        return 'Test failed (No result was received from Coralogix or the response was unexpected `' + \
               json.dumps(results_raw) + '`)'


def fetch_incidents(
        cgx_private_key,
        cgx_endpoint_url,
        incidents_base_query,
        application_name,
        subsystem_name,
        severity,
        incidents_name_field,
        incidents_first_fetch_range,
        incidents_max_fetch,
        columns_to_include_in_human_readable):
    """
    This method handles querying Coralogix for incidents by using the configured query and parameters

    Args:
        cgx_private_key - String, Coralogix Private Key
        cgx_endpoint_url - String, Coralogix Cluster Base URL for the Coralogix ES-API
        application_name - String, The
        subsystem_name - String,
        severity - String

    Returns:
        Returns the incidents found in Coralogix
    """

    last_run_timestamp = "now-" + str(incidents_first_fetch_range) + "d"
    if "last_run_timestamp" in demisto.getLastRun():
        last_run_timestamp = demisto.getLastRun().get('last_run_timestamp', last_run_timestamp)
    raw_data = coralogix_search_command(
        cgx_private_key=cgx_private_key,
        cgx_endpoint_url=cgx_endpoint_url,
        query=incidents_base_query,
        application_name=application_name,
        subsystem_name=subsystem_name,
        severity=severity,
        columns_to_include_in_human_readable=columns_to_include_in_human_readable,
        since_timestamp=last_run_timestamp,
        max_items_to_retrieve=incidents_max_fetch
    ).raw_response

    newest_incident_date_obj = datetime(year=1970, month=1, day=1)
    incidents = []
    if "hits" in raw_data and "hits" in raw_data["hits"]:
        for document in raw_data["hits"]["hits"]:
            flattened_document = flatten_json(document["_source"])
            incident_date = flattened_document['coralogix.timestamp']
            incident = {
                'name': flattened_document[incidents_name_field],
                'occurred': incident_date + "Z",
                'rawJSON': json.dumps(flattened_document)
            }
            incidents.append(incident)
            incident_date_obj = dateutil.parser.parse(incident_date)
            if incident_date_obj.replace(tzinfo=UTC).timestamp() > \
                    newest_incident_date_obj.replace(tzinfo=UTC).timestamp():
                newest_incident_date_obj = incident_date_obj

    demisto.setLastRun({"last_run_timestamp": newest_incident_date_obj.replace(tzinfo=UTC).timestamp()})
    return incidents


def main():
    # CONSTANTS

    columns_to_include_in_human_readable = [
        'coralogix.timestamp',
        'coralogix.severity_str',
        'coralogix.metadata.applicationName',
        'coralogix.metadata.subsystemName',
        'security.source_ip',
        'security.destination_ip',
        'security.event_type',
        'security.source_port',
        'security.destination_port',
        'security.connection_state_description',
        'security.protocol',
        'security.local_orig',
        'security.local_respond',
        'security.total_bytes',
        'security.query',
        'security.query_type_name',
        'security.rcode_name',
        'security.ra',
        'security.rd',
        'awsRegion',
        'eventName',
        'eventSource',
        'sourceIPAddress',
        'userIdentity.sessionContext.sessionIssuer.userName',
        'userIdentity.type',
        'recipientAccountId',
        'source_ip',
        'destination_ip',
        'source_port',
        'destination_port',
        'protocol'
    ]
    default_incidents_query = "alert_type_id:\"53d222e2-e7b2-4fa6-80d4-9935425d47dd\""
    default_incidents_first_fetch_range = '3'
    default_incidents_max_fetch = '50'
    default_incident_description_field = "alert_name"
    default_max_items_to_retrieve = "50"

    # PARSE AND VALIDATE INTEGRATION PARAMS
    private_key = strip_or_empty(demisto.params().get('privatekey', ''))

    # get the service API url
    tags_api_url = urljoin(strip_or_empty(demisto.params().get('webapi_url', '')), '/api/v1/addTagPost')
    search_api_url = urljoin(strip_or_empty(demisto.params().get('esapi_url', '')), '/*/_search')

    # Get other parameters
    tag_application_name = strip_or_empty(demisto.params().get('app_name', ''))
    tag_subsystem_name = strip_or_empty(demisto.params().get('subsystem_name', ''))
    incidents_first_fetch_range_raw = strip_or_empty(demisto.params().get('incidents_first_fetch_range',
                                                                          default_incidents_first_fetch_range))
    incidents_max_fetch_raw = strip_or_empty(demisto.params().get('incidents_max_fetch', default_incidents_max_fetch))
    incidents_query = strip_or_empty(demisto.params().get('incidents_query', default_incidents_max_fetch))
    incidents_name_field = strip_or_empty(demisto.params().get('incident_description_field', default_incident_description_field))
    incidents_application_name = strip_or_empty(demisto.params().get('incidents_application_name', ''))
    incidents_subsystem_name = strip_or_empty(demisto.params().get('incidents_subsystem_name', ''))
    incidents_severity = strip_or_empty(demisto.params().get('incidents_severity', ''))

    # Assigning defaults if needed
    if len(incidents_query) == 0:
        incidents_query = default_incidents_query
    if len(incidents_name_field) == 0:
        incidents_name_field = default_incident_description_field
    if len(incidents_first_fetch_range_raw) == 0 or not incidents_first_fetch_range_raw.isnumeric():
        incidents_first_fetch_range_raw = default_incidents_first_fetch_range
    if len(incidents_max_fetch_raw) == 0 or not incidents_max_fetch_raw.isnumeric():
        incidents_max_fetch_raw = default_incidents_max_fetch

    incidents_first_fetch_range = int(incidents_first_fetch_range_raw)
    incidents_max_fetch = int(incidents_max_fetch_raw)

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(cgx_endpoint_url=search_api_url, cgx_private_key=private_key)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            if len(incidents_query) > 0 and len(incidents_name_field) > 0:
                incidents = fetch_incidents(
                    cgx_private_key=private_key,
                    cgx_endpoint_url=search_api_url,
                    incidents_base_query=incidents_query,
                    application_name=incidents_application_name,
                    subsystem_name=incidents_subsystem_name,
                    severity=incidents_severity,
                    incidents_name_field=incidents_name_field,
                    columns_to_include_in_human_readable=columns_to_include_in_human_readable,
                    incidents_max_fetch=incidents_max_fetch,
                    incidents_first_fetch_range=incidents_first_fetch_range
                )
                demisto.incidents(incidents)
            else:
                if len(incidents_query) == 0:
                    raise ValueError("ERROR: Cannot fetch incidents. No incidents query defined.")
                if len(incidents_name_field) == 0:
                    raise ValueError("ERROR: Cannot fetch incidents. The incident_description_field is empty.")
                demisto.incidents([])
        elif demisto.command() == 'coralogix-tag':
            if "name" in demisto.args():
                tag_name = strip_or_empty(demisto.args().get("name", ''))
            else:
                raise Exception("Tag name is missing")
            if "timestamp" in demisto.args():
                tag_timestamp = strip_or_empty(demisto.args().get("timestamp", ''))
            else:
                tag_timestamp = ""
            if "icon_url" in demisto.args():
                tag_icon_url = strip_or_empty(demisto.args().get("icon_url", ''))
            else:
                tag_icon_url = ""
            return_results(coralogix_tag_command(
                private_key=private_key,
                coralogix_url=tags_api_url,
                application_name=tag_application_name,
                subsystem_name=tag_subsystem_name,
                tag_name=tag_name,
                tag_timestamp=tag_timestamp,
                tag_icon_url=tag_icon_url
            ))
        elif demisto.command() == 'coralogix-search':
            if "query" in demisto.args():
                query = demisto.args()["query"]
            else:
                raise Exception("No query specified")
            if "app_name" in demisto.args():
                search_app_name = strip_or_empty(demisto.args().get("app_name", ''))
            else:
                search_app_name = ""
            if "subsystem_name" in demisto.args():
                search_subsystem_name = strip_or_empty(demisto.args().get("subsystem_name", ''))
            else:
                search_subsystem_name = ""
            if "severity" in demisto.args():
                search_severity = strip_or_empty(demisto.args().get("severity", ''))
            else:
                search_severity = ""
            if "since_timestamp" in demisto.args():
                since_timestamp = strip_or_empty(demisto.args().get("since_timestamp", ''))
            else:
                since_timestamp = None
            if "to_timestamp" in demisto.args():
                to_timestamp = strip_or_empty(demisto.args().get("to_timestamp", ''))
            else:
                to_timestamp = "now"
            if "max_items_to_retrieve" in demisto.args():
                max_items_to_retrieve_raw = strip_or_empty(demisto.args().get("max_items_to_retrieve", ''))
                if not max_items_to_retrieve_raw.isnumeric():
                    max_items_to_retrieve_raw = default_max_items_to_retrieve
            else:
                max_items_to_retrieve_raw = default_max_items_to_retrieve
            max_items_to_retrieve = int(max_items_to_retrieve_raw)

            return_results(coralogix_search_command(
                cgx_private_key=private_key,
                cgx_endpoint_url=search_api_url,
                query=query,
                application_name=search_app_name,
                subsystem_name=search_subsystem_name,
                severity=search_severity,
                since_timestamp=since_timestamp,
                to_timestamp=to_timestamp,
                max_items_to_retrieve=max_items_to_retrieve,
                columns_to_include_in_human_readable=columns_to_include_in_human_readable
            ))
        else:
            demisto.error("Unknown command")

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
