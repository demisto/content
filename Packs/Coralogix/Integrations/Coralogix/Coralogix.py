import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
import urllib3
import datetime
import dateutil.parser
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''

''' SUPPLEMENTAL FUNCTIONS '''
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
def elastic_output_as_table(raw_elastic_json_obj, filter_out_columns):
    """
    This supplemental method converts an Elasticsearch output JSON object to a Demisto table

    Args:
         raw_elastic_json_obj - The raw Elasticsearch output as received from the Elasticsearch API
         filter_out_columns - A strings array which contains the list of columns to remove from the output
    Returns:
         An object that represents a Demisto table with the data from the Elasticsearch output
    """

    # scan for columns list
    columns = []
    for raw_row in raw_elastic_json_obj["hits"]["hits"]:
        raw_row_flattened = flatten_json(raw_row["_source"])
        for key in raw_row_flattened:
            if key not in columns and key not in filter_out_columns:
                columns.append(key)

    # sort columns
    columns.sort()

    # fill in the table and the raw contents objects
    table = []
    raw_contents = []
    table.append(columns)
    for raw_row in raw_elastic_json_obj["hits"]["hits"]:
        raw_row_flattened = flatten_json(raw_row["_source"])
        row = [None] * len(columns)
        for key in raw_row_flattened:
            if key not in filter_out_columns:
                row[columns.index(key)] = raw_row_flattened[key]
        table.append(row)
        raw_contents.append(raw_row_flattened)

    return {"human_readable_table": table, "raw_contents": raw_contents}

''' COMMANDS '''
def coralogix_search_command(cgx_private_key, cgx_endpoint_url, query, exclude_columns, results_as_table, application_name, subsystem_name, severity, since_timestamp=-1):
    """
    This method handles the cgx_search command which allows the user to search for data on a Coralogix account

    Args:
        cgx_private_key - String, Coralogix Private Key (From the integration's settings page)
        cgx_endpoint_url - Coralogix ES-API base URL (From the integration's settings page)
        query - The Lucene query to send to Coralogix
        exclude_columns - Strings Array, Columns to exclude from the result (Relevant only for table output mode)
        results_as_table - Boolean, Whether or not to return the result of the query as a table (if not it will be retrieved as a JSON object)
        application_name - String, The Coralogix application name to look for (optional)
        subsystem_name - String, The Coralogix subsystem name to look for (optional)
        severity - String, The Coralogix severity to look for (optional)
    Returns:
        Either a Demisto table object or a JSON object with the search results
    """
    http = urllib3.PoolManager()
    pre_query = ""
    if len(application_name.strip()) > 0:
        pre_query = 'coralogix.metadata.applicationName:"' + application_name.strip() + '"'
    if len(pre_query.strip()) > 0:
        pre_query = pre_query + ' AND '
    if len(subsystem_name.strip()) > 0:
        pre_query = pre_query + 'coralogix.metadata.subsystemName:"' + subsystem_name.strip() + '"'
    if len(pre_query.strip()) > 0:
        pre_query = pre_query + ' AND '
    if len(severity.strip()) > 0:
        pre_query = pre_query + 'coralogix.severity_str:"' + severity.strip() + '"'
    if len(pre_query.strip()) > 0:
        query = '(' + pre_query + ') AND (' + query + ')'

    if since_timestamp is not None and since_timestamp >= 0:
        request_data = {
            "bool": {
                "must": [
                    {
                        "query": {
                            "query_string": {
                                "query": query
                            }
                        }
                    },
                    {
                        "range": {
                            "coralogix.timestamp": {
                                "gte": since_timestamp,
                                "lt": "now"
                            }
                        }
                    }
                ]
            }
        }
    else:
        request_data = {
            "query": {
                "query_string": {
                    "query": query
                }
            }
        }
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
    if results_as_table:
        if 'hits' in results_raw and 'hits' in results_raw['hits']:
            formatted_data = elastic_output_as_table(raw_elastic_json_obj=results_raw, filter_out_columns=exclude_columns)
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': formatted_data['raw_contents'],
                'ReadableContentsFormat': formats['table'],
                'HumanReadable': formatted_data['human_readable_table']
            }
        else:
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': [],
                'ReadableContentsFormat': formats['table'],
                'HumanReadable': "No results found"
            }
    else:
        return results_raw

def coralogix_tag_command(private_key, coralogix_url, application_name, subsystem_name, tag_name, tag_timestamp ="", tag_icon_url =""):
    """
    This method handles the cgx_tag command which allows the user to tag a certain timestamp on Coralogix (for example to mark the time at which an incident has occurred)

    Args:
        private_key - String, Coralogix Private Key (From the integration's settings page)
        coralogix_url - String, Coralogix Web-API base URL (From the integration's settings page)
        application_name - String, The application name that will be associated with the tag (Would probably be something like 'Demisto')
        subsystem_name - String, The subsystem name that will be associated with the tag (Would probably be something like 'Demisto')
        tag_name - String, The name of the tag that will be created
        tag_timestamp - String, The date at which to put the tag in Coralogix. (Optional, if not set the current time will be used by Coralogix)
        tag_icon_url - String, A URL for an image that will be used in the tag. Cannot exceed 50KB. (Optional, if not set, Coralogix will automatically choose an image)
    Returns:
        The raw response from Coralogix WebAPI. If it is JSON parsable it will return it as an object, otherwise - as a string.
    """
    query_string_params = {
        'key': private_key,
        'application': application_name,
        'subsystem': subsystem_name,
        'name': tag_name
    }
    if len(tag_timestamp.strip()) > 0:
        query_string_params["timestamp"] = tag_timestamp.strip()
    if len(tag_icon_url.strip()) > 0:
        query_string_params["iconUrl"] = tag_icon_url.strip()

    demisto.info('Calling `' + coralogix_url + '` using GET with these args ' + json.dumps(query_string_params) + ' ...')
    response = requests.post(coralogix_url, params=query_string_params)
    try:
        return json.loads(response.text)
    except json.JSONDecodeError:
        return response.text

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
        return 'Test failed (No result was received from Coralogix or the response was unexpected `' + json.dumps(results_raw) + '`)'

def fetch_incidents(cgx_private_key, cgx_endpoint_url, incidents_base_query, application_name, subsystem_name, severity, incidents_name_field):
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

    last_run_timestamp = -1
    if "last_run_timestamp" in demisto.getLastRun():
        last_run_timestamp = demisto.getLastRun().get('last_run_timestamp', -1)
    raw_data = coralogix_search_command(
        cgx_private_key=cgx_private_key,
        cgx_endpoint_url=cgx_endpoint_url,
        query=incidents_base_query,
        application_name=application_name,
        subsystem_name=subsystem_name,
        severity=severity,
        exclude_columns=[],
        results_as_table=False,
        since_timestamp=last_run_timestamp
    )

    newest_incident_date_obj = datetime.datetime(year=1970, month=1, day=1)
    incidents = []
    if "hits" in raw_data and "hits" in raw_data["hits"]:
        for document in raw_data["hits"]["hits"]:
            flattened_document = flatten_json(document["_source"])
            incident_date = flattened_document['@timestamp']
            incident = {
                'name': flattened_document[incidents_name_field],
                'occurred': incident_date,
                'rawJSON': json.dumps(flattened_document)
            }
            incidents.append(incident)
            incident_date_obj = dateutil.parser.parse(incident_date)
            if incident_date_obj.replace(tzinfo=datetime.timezone.utc).timestamp() > newest_incident_date_obj.replace(tzinfo=datetime.timezone.utc).timestamp():
                newest_incident_date_obj = incident_date_obj

    demisto.setLastRun({"last_run_timestamp": newest_incident_date_obj.replace(tzinfo=datetime.timezone.utc).timestamp()})
    return incidents

def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    private_key = demisto.params().get('privatekey', '').strip()

    # get the service API url
    tags_api_url = urljoin(demisto.params().get('webapi_url', '').strip(), '/api/v1/addTagPost')
    search_api_url = urljoin(demisto.params().get('esapi_url', '').strip(), '/*/_search')

    tag_application_name = demisto.params().get('app_name', '').strip()
    tag_subsystem_name = demisto.params().get('subsystem_name', '').strip()

    if 'incidents_query' in demisto.params() and demisto.params()['incidents_query'] is not None:
        incidents_query = demisto.params().get('incidents_query', '').strip()
    else:
        incidents_query = "alert_type:\"53d222e2-e7b2-4fa6-80d4-9935425d47dd\""
    if 'incidents_application_name' in demisto.params() and demisto.params()['incidents_application_name'] is not None:
        incidents_application_name = demisto.params().get('incidents_application_name', '').strip()
    else:
        incidents_application_name = ""
    if 'incidents_subsystem_name' in demisto.params() and demisto.params()['incidents_subsystem_name'] is not None:
        incidents_subsystem_name = demisto.params().get('incidents_subsystem_name', '').strip()
    else:
        incidents_subsystem_name = ""
    if 'incidents_severity' in demisto.params() and demisto.params()['incidents_severity'] is not None:
        incidents_severity = demisto.params().get('incidents_severity', '').strip()
    else:
        incidents_severity = ""
    if 'incident_description_field' in demisto.params() and demisto.params()['incident_description_field'] is not None:
        incidents_name_field = demisto.params().get('incident_description_field', '').strip()
    else:
        incidents_name_field = "alert_name"

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(cgx_endpoint_url=search_api_url, cgx_private_key=private_key)
            demisto.results(result)
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            if len(incidents_query.strip()) > 0 and len(incidents_name_field.strip()) > 0:
                incidents = fetch_incidents(
                    cgx_private_key=private_key,
                    cgx_endpoint_url=search_api_url,
                    incidents_base_query=incidents_query,
                    application_name=incidents_application_name,
                    subsystem_name=incidents_subsystem_name,
                    severity=incidents_severity,
                    incidents_name_field=incidents_name_field
                )
                demisto.incidents(incidents)
            else:
                if len(incidents_query.strip()) == 0:
                    demisto.error("ERROR: Cannot fetch incidents. No incidents query defined.")
                if len(incidents_name_field.strip()) == 0:
                    demisto.error("ERROR: Cannot fetch incidents. The incident_description_field is empty.")
                demisto.incidents([])
        elif demisto.command() == 'coralogix_tag':
            if "name" in demisto.args():
                tag_name = demisto.args()["name"].strip()
            else:
                raise Exception("Tag name is missing")
            if "timestamp" in demisto.args():
                tag_timestamp = demisto.args()["timestamp"].strip()
            else:
                tag_timestamp = ""
            if "icon_url" in demisto.args():
                tag_icon_url = demisto.args()["icon_url"].strip()
            else:
                tag_icon_url = ""
            demisto.results(coralogix_tag_command(
                private_key=private_key,
                coralogix_url=tags_api_url,
                application_name=tag_application_name,
                subsystem_name=tag_subsystem_name,
                tag_name=tag_name,
                tag_timestamp=tag_timestamp,
                tag_icon_url=tag_icon_url
            ))
        elif demisto.command() == 'coralogix_search':
            if "query" in demisto.args():
                query = demisto.args()["query"].strip()
            else:
                raise Exception("No query specified")
            if "exclude" in demisto.args():
                exclude_columns = demisto.args()["exclude"].strip().split(',')
            else:
                exclude_columns = []
            if "as_table" in demisto.args():
                results_as_table = argToBoolean(demisto.args()["as_table"])
            else:
                results_as_table = False
            if "app_name" in demisto.args():
                search_app_name = demisto.args()["app_name"].strip()
            else:
                search_app_name = ""
            if "subsystem_name" in demisto.args():
                search_subsystem_name = demisto.args()["subsystem_name"].strip()
            else:
                search_subsystem_name = ""
            if "severity" in demisto.args():
                search_severity = demisto.args()["severity"].strip()
            else:
                search_severity = ""

            demisto.results(coralogix_search_command(
                cgx_private_key=private_key,
                cgx_endpoint_url=search_api_url,
                query=query,
                exclude_columns=exclude_columns,
                results_as_table=results_as_table,
                application_name=search_app_name,
                subsystem_name=search_subsystem_name,
                severity=search_severity
            ))
        else:
            demisto.error("Unknown command")

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
