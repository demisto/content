import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
""" IMPORTS """

import os
import json
import urllib3
from google.cloud import bigquery
from datetime import date
import hashlib


# Disable insecure warnings
urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

TEST_QUERY = ('SELECT name FROM `bigquery-public-data.usa_names.usa_1910_2013` '
              'WHERE state = "TX" '
              'LIMIT 10')


''' HELPER FUNCTIONS '''


def represents_bool(string_var):
    return string_var.lower() == 'false' or string_var.lower() == 'true'


def str_to_bool(str_representing_bool):
    return str_representing_bool.lower() == "true"


def bool_arg_set_to_true(arg):
    return arg and str_to_bool(arg)


def start_and_return_bigquery_client(google_service_creds_json_string):
    cur_directory_path = os.getcwd()
    creds_file_name = '{0}.json'.format(demisto.uniqueFile())
    path_to_save_creds_file = os.path.join(cur_directory_path, creds_file_name)
    with open(path_to_save_creds_file, "w") as creds_file:
        json.dump(json.loads(google_service_creds_json_string), creds_file)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = path_to_save_creds_file
        creds_file.close()
    bigquery_client = bigquery.Client()
    return bigquery_client


def validate_args_for_query_job_config(allow_large_results, priority, use_query_cache, use_legacy_sql, dry_run,
                                       destination_table, write_disposition):
    if allow_large_results and not represents_bool(allow_large_results):
        return_error("Error: allow_large_results must have a boolean value.")
    if bool_arg_set_to_true(allow_large_results) and not destination_table:
        return_error("Error: allow_large_results could only be set to True if a destination table is provided as well.")
    if bool_arg_set_to_true(allow_large_results) and not bool_arg_set_to_true(use_legacy_sql):
        return_error("Error: allow_large_results could be set to True only if use_legacy_sql is set to True.")
    if use_query_cache and not represents_bool(use_query_cache):
        return_error("Error: use_query_cache must have a boolean value.")
    if bool_arg_set_to_true(use_query_cache) and destination_table:
        return_error("Error: use_query_cache cannot be set to True if a destination_table is set")
    if use_legacy_sql and not represents_bool(use_legacy_sql):
        return_error("Error: use_legacy_sql must have a boolean value.")
    if dry_run and not represents_bool(dry_run):
        return_error("Error: dry_run must have a boolean value.")
    if priority and not (priority == 'INTERACTIVE' or priority == 'BATCH'):
        return_error("Error: priority must have a value of INTERACTIVE or BATCH.")
    if write_disposition and not (write_disposition == 'WRITE_TRUNCATE' or write_disposition == 'WRITE_APPEND'
                                  or write_disposition == 'WRITE_EMPTY'):
        return_error("Error: write_disposition must have a value of WRITE_TRUNCATE, WRITE_APPEND or WRITE_EMPTY.")


def build_query_job_config(allow_large_results, default_dataset_string, destination_table, dry_run, priority,
                           use_query_cache, use_legacy_sql, kms_key_name, write_disposition):
    validate_args_for_query_job_config(allow_large_results, priority, use_query_cache, use_legacy_sql, dry_run,
                                       destination_table, write_disposition)
    query_job_config = bigquery.QueryJobConfig()
    if allow_large_results:
        query_job_config.allow_large_results = str_to_bool(allow_large_results)
    if default_dataset_string:
        query_job_config.default_dataset = default_dataset_string
    if destination_table:
        query_job_config.destination = destination_table
    if kms_key_name:
        query_job_config.destination_encryption_configuration = bigquery.table.EncryptionConfiguration(kms_key_name)
    if dry_run:
        query_job_config.dry_run = str_to_bool(dry_run)
    if use_legacy_sql:
        query_job_config.use_legacy_sql = str_to_bool(use_legacy_sql)
    if use_query_cache:
        query_job_config.use_query_cache = str_to_bool(use_query_cache)
    if priority:
        query_job_config.priority = priority
    if write_disposition:
        query_job_config.write_disposition = write_disposition

    return query_job_config


def convert_to_string(field_value):
    if isinstance(field_value, datetime):
        return field_value.strftime("%m/%d/%Y %H:%M:%S")
    if isinstance(field_value, date):
        return field_value.strftime("%m/%d/%Y")
    if isinstance(field_value, bytes):
        return field_value.decode('utf-8')
    return field_value


''' COMMANDS + REQUESTS FUNCTIONS '''


def query(query_string, project_id, location, allow_large_results, default_dataset, destination, kms_key_name, dry_run,
          priority, use_query_cache, use_legacy_sql,
          google_service_creds, job_id, write_disposition):
    bigquery_client = start_and_return_bigquery_client(google_service_creds)
    job_config = build_query_job_config(allow_large_results, default_dataset, destination, dry_run, priority,
                                        use_query_cache, use_legacy_sql, kms_key_name, write_disposition)
    query_job = bigquery_client.query(query=query_string, job_config=job_config, location=location,
                                      job_id=job_id, project=project_id)
    if not (dry_run and str_to_bool(dry_run)):
        query_results = query_job.result()
        return query_results
    else:
        # if dry run is activated, the results (number of bytes the query will process) are returned in the job itself
        return query_job


def get_query_results(query_to_run=None):
    args = demisto.args()
    query_to_run = query_to_run or args['query']
    project_id = args.get('project_id', None)
    location = args.get('location', None)
    allow_large_results = args.get('allow_large_results', None)
    default_dataset = args.get('default_dataset', None)
    destination_table = args.get('destination_table', None)
    kms_key_name = args.get('kms_key_name', None)
    dry_run = args.get('dry_run', None)
    priority = args.get('priority', None)
    use_query_cache = args.get('use_query_cache', None)
    use_legacy_sql = args.get('use_legacy_sql', None)
    google_service_creds = demisto.params().get('credentials_google_service', {}).get(
        'password') or demisto.params()['google_service_creds']
    job_id = args.get('job_id', None)
    if not google_service_creds:
        raise DemistoException('Google service account JSON must be provided.')
    write_disposition = args.get('write_disposition', None)
    query_results = query(query_to_run, project_id, location, allow_large_results, default_dataset,
                          destination_table, kms_key_name, dry_run, priority, use_query_cache, use_legacy_sql,
                          google_service_creds, job_id, write_disposition)
    return query_results


def query_command(query_to_run=None):
    query_results = get_query_results(query_to_run)
    args = demisto.args()
    dry_run = args.get('dry_run', None)
    context = {}
    rows_contexts = []
    human_readable = 'No results found.'
    if dry_run and str_to_bool(dry_run):
        human_readable = '### Dry run results: \n This query will process {0} ' \
                         'bytes'.format(query_results.total_bytes_processed)

    else:

        for row in query_results:
            row_context = {underscoreToCamelCase(k): convert_to_string(v) for k, v in row.items()}
            rows_contexts.append(row_context)

        if rows_contexts:

            context['BigQuery(val.Query && val.Query == obj.Query)'] = {
                'Query': args['query'],
                'Row': rows_contexts
            }
            title = 'BigQuery Query Results'
            human_readable = tableToMarkdown(title, rows_contexts, removeNull=True)

    return_outputs(
        readable_output=human_readable,
        outputs=context,
        raw_response=rows_contexts
    )


def get_incident_id(row):
    """
    In BigQuery, each row is a separate incident.
    To enable the deduplication of incidents, we would like to generate a unique ID for each row.
    We achieve that goal by using several common fields, that are, combined, a unique identifier.
    """
    additional_fields = row.get('additional_fields')
    generated = row.get('generatedTime') or row.get('generated_time') or row.get('GeneratedTime')
    event_id = row.get('event_id') or row.get('EventId') or row.get('eventId')
    instance_id = row.get('instance_id') or row.get('InstanceId') or row.get('instanceId')
    agent_id = row.get('agent_id') or row.get('AgentId') or row.get('agentId')
    data = [additional_fields, generated, event_id, instance_id, agent_id]
    row_data_string = ''
    for data_field in data:
        row_data_string += f'{data_field}_'
    row_id = hashlib.md5(row_data_string.encode('utf-8')).hexdigest()  # nosec
    return row_id


def get_last_run_date():
    """
    Calculate the time from which to start fetching incidents.
    """
    last_date = demisto.getLastRun().get('last_date')
    demisto.debug('[BigQuery Debug] last_date is: {}'.format(last_date))

    if last_date is None:
        first_fetch_time = demisto.params().get('first_fetch_time', '1 days')
        first_fetch, _ = parse_date_range(first_fetch_time, date_format='%Y-%m-%d %H:%M:%S.%f')
        last_date = first_fetch
        demisto.debug('[BigQuery Debug] FIRST RUN - last_date is: {}'.format(last_date))

    return last_date


def build_fetch_query(last_date):
    """
    Build the fetch query, given the user's input query.
    """
    fixed_query = demisto.params()["fetch_query"]

    if "WHERE" in fixed_query:
        fixed_query += " AND"
    else:
        fixed_query += " WHERE"

    fetch_time_field = demisto.params().get("fetch_time_field", "CreationTime")
    fetch_query = "{} `{}` > \"{}\"".format(fixed_query, fetch_time_field, last_date)
    return fetch_query


def row_to_incident(row):
    """
    Transform a Google BigQuery row to an incident's format.
    """
    incident = {}
    raw = {underscoreToCamelCase(k): convert_to_string(v) for k, v in row.items()}
    incident["rawJSON"] = json.dumps(raw)
    incident_name_field = demisto.params().get("incident_name_field")
    if incident_name_field and incident_name_field in raw:
        incident["name"] = raw[incident_name_field]
    return incident


def get_incident_time(incident):
    incident_row = json.loads(incident["rawJSON"])
    return get_row_date_string(incident_row)


def get_row_date_string(row):
    """
    Given a row, retrieve the date representing the time in which it was created.
    According to our testing, on some cases the creation time is spelled 'creation_time',
    and on other cases 'CreationTime'.
    Moreover, it could be something else entirely, specified by the user.
    On each case, the format is different as well.
    """
    row_date_field = demisto.params().get("fetch_time_field", "creation_time")
    row_date = row.get(row_date_field)
    if row_date is None:
        demisto.debug("[BigQuery Debug] missing creation_time, trying CreationTime: {}".format(row))
        row_date_str = row.get("CreationTime")
        if row_date_str is not None:
            row_date = datetime.strptime(row_date_str, '%Y-%m-%d %H:%M:%S')
            row_date_str = row_date.strftime('%Y-%m-%d %H:%M:%S.%f')
    else:
        row_date_str = row_date.strftime('%Y-%m-%d %H:%M:%S.%f')
    if row_date_str is None:
        demisto.debug("[BigQuery Debug] missing creation time completely: {}".format(row))
        return_error("[BigQuery Debug] missing creation time completely: {}".format(row))
    return row_date_str


def get_max_incident_time(new_incidents):
    """
    Given the newly fetched incidents, return the time of the most recent one.
    """
    def incident_to_timestamp(incident):
        incident_time = get_incident_time(incident)
        return datetime.strptime(incident_time, '%Y-%m-%d %H:%M:%S.%f')

    incident_with_latest_timestamp = max(new_incidents, key=lambda inc: incident_to_timestamp(inc))
    return get_incident_time(incident_with_latest_timestamp)


def remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str):
    """
    To avoid a continuously growing context size, we must delete outdated incident IDs.
    To do that, we delete any ID that dates before the start time of the current fetch.
    """
    new_found_ids = {}
    latest_incident_time = datetime.strptime(latest_incident_time_str, '%Y-%m-%d %H:%M:%S.%f')

    for incident_id, date_str in found_incidents_ids.items():
        incident_time = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')
        if incident_time >= latest_incident_time:
            new_found_ids[incident_id] = date_str

    return new_found_ids


def verify_params():
    params = demisto.params()
    if not params.get('first_fetch_time'):
        return_error('Error: fetch start time must be supplied.')
    if not params.get('fetch_query'):
        return_error('Error: fetch query must be supplied.')
    if not params.get('fetch_time_field'):
        return_error('Error: the time field you want us to sort incidents by must be supplied.')


def fetch_incidents():
    verify_params()
    latest_incident_time_str = get_last_run_date()
    fetch_query = build_fetch_query(latest_incident_time_str)
    demisto.debug("[BigQuery Debug] fetch query with date is: {}".format(fetch_query))
    fetch_limit = arg_to_number(demisto.params().get('max_fetch') or 50)

    bigquery_rows = list(get_query_results(fetch_query))

    demisto.debug("[BigQuery Debug] number of results is: {}".format(len(bigquery_rows)))
    if len(bigquery_rows) > 0:
        demisto.debug("[BigQuery Debug] first row is: {}".format(bigquery_rows[0]))
        demisto.debug("[BigQuery Debug] last row is: {}".format(bigquery_rows[-1]))

    new_incidents = []  # type: ignore
    found_incidents_ids = demisto.getLastRun().get('found_ids', {})

    for i in range(len(bigquery_rows) - 1, - 1, -1):
        # We iterate backwards since the incidents' time is in increasing order
        if len(new_incidents) == fetch_limit:
            break
        row = bigquery_rows[i]
        row_incident_id = get_incident_id(row)
        row_date = get_row_date_string(row)
        if row_incident_id in found_incidents_ids:
            continue

        found_incidents_ids[row_incident_id] = row_date
        demisto.debug("[BigQuery Debug] cur row: {}".format(row))
        incident = row_to_incident(row)
        new_incidents.append(incident)

    demisto.debug(
        "[BigQuery Debug] new_incidents is: {}\nbigquery_rows is: {}".format(new_incidents, len(bigquery_rows)))

    if 0 < len(new_incidents) < fetch_limit:  # type: ignore
        demisto.debug("[BigQuery Debug] Less than limit")
        latest_incident_time_str = get_max_incident_time(new_incidents)
        found_incidents_ids = remove_outdated_incident_ids(found_incidents_ids, latest_incident_time_str)

    next_run = {
        "last_date": latest_incident_time_str,
        "found_ids": found_incidents_ids
    }
    demisto.debug("[BigQuery Debug] next run is: {}".format(next_run))
    demisto.setLastRun(next_run)

    demisto.incidents(new_incidents)


def test_module():
    """
    Perform basic get request to get item samples
    """
    try:
        google_service_creds = demisto.params().get('credentials_google_service', {}).get(
            'password') or demisto.params()['google_service_creds']
        bigquery_client = start_and_return_bigquery_client(google_service_creds)
        query_job = bigquery_client.query(TEST_QUERY)
        query_results = query_job.result()
        results_rows_iterator = iter(query_results)
        next(results_rows_iterator)
        demisto.results("ok")
    except Exception as ex:
        return_error("Authentication error: credentials JSON provided is invalid.\n Exception recieved:"
                     "{}".format(ex))


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'bigquery-query':
        search_query = demisto.args().get('query')
        query_command(search_query)
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
