import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

import json
import os
from datetime import date, datetime

import requests
from dateparser import parse
from google.cloud import bigquery

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

TEST_QUERY = ('SELECT name FROM `bigquery-public-data.usa_names.usa_1910_2013` '
              'WHERE state = "TX" '
              'LIMIT 10')

FETCH_QUERY = demisto.params()['querytoRun']


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


def convert_to_string_if_datetime(object_that_may_be_datetime):
    if isinstance(object_that_may_be_datetime, datetime):
        return object_that_may_be_datetime.strftime("%m/%d/%Y %H:%M:%S")
    if isinstance(object_that_may_be_datetime, date):
        return object_that_may_be_datetime.strftime("%m/%d/%Y")
    else:
        return object_that_may_be_datetime


''' XDR SYNC FUNCTIONS '''


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


def query_command(args):
    query_to_run = args['query']
    project_id = args.get('project_id', None)
    location = args.get('location', None)
    incidentObj = args.get('incident', False)
    allow_large_results = args.get('allow_large_results', None)
    default_dataset = args.get('default_dataset', None)
    destination_table = args.get('destination_table', None)
    kms_key_name = args.get('kms_key_name', None)
    dry_run = args.get('dry_run', None)
    priority = args.get('priority', None)
    use_query_cache = args.get('use_query_cache', None)
    use_legacy_sql = args.get('use_legacy_sql', None)
    google_service_creds = demisto.params()['google_service_creds']
    job_id = args.get('job_id', None)
    write_disposition = args.get('write_disposition', None)
    query_results = query(query_to_run, project_id, location, allow_large_results, default_dataset,
                          destination_table, kms_key_name, dry_run, priority, use_query_cache, use_legacy_sql,
                          google_service_creds, job_id, write_disposition)

    context = {}
    rows_contexts = []
    human_readable = 'No results found.'
    if dry_run and str_to_bool(dry_run):
        human_readable = '### Dry run results: \n This query will process {0} ' \
                         'bytes'.format(query_results.total_bytes_processed)

    else:

        for row in query_results:
            row_context = {k: convert_to_string_if_datetime(v) for k, v in row.items()}
            rows_contexts.append(row_context)

        if rows_contexts:

            context['BigQuery(val.Query && val.Query == obj.Query)'] = {
                'Query': args['query'],
                'Row': rows_contexts
            }
            title = 'BigQuery Query Results'
            human_readable = tableToMarkdown(title, rows_contexts, removeNull=True)
    if incidentObj is False:
        return rows_contexts
    else:
        incidents = []
        for index, row in enumerate(rows_contexts):
            incident = {
                'name': f'Query Result #{index}',
                'occurred': datetime.now().isoformat().split(".")[0] + "Z",
                'rawJSON': json.dumps(row)
            }
            incidents.append(incident)
        return incidents


def get_data(remote_incident_id, last_update):
    identifierKey = demisto.params()['identifierKey']
    syncTable = demisto.params()['sync_table']
    lastmodifiedKey = demisto.params()['lastmodifiedKey']
    record_modified_date = last_update.split(".")[0].replace("T", " ")
    return query_command({'query': FETCH_QUERY + f" AND CAST({identifierKey} AS STRING)='{remote_incident_id}' AND TIMESTAMP({lastmodifiedKey}) > TIMESTAMP('{record_modified_date}') LIMIT 1", 'incident': False})[0]


def get_modified_remote_data_command(args):
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    last_update_bq = last_update.split(".")[0].replace("T", " ")
    modified_records_ids = []
    identifierKey = demisto.params()['identifierKey']
    syncTable = demisto.params()['sync_table']
    lastmodifiedKey = demisto.params()['lastmodifiedKey']
    demisto.debug(f'Google BigQuery : * START * Performing get-modified-remote-data command. Last update is: {last_update}')
    qres = query_command(
        {'query': f"SELECT DISTINCT {identifierKey} FROM `{syncTable}` WHERE TIMESTAMP({lastmodifiedKey}) > TIMESTAMP({last_update_bq})", 'incident': False})
    for item in qres:
        modified_records_ids.append(item[f'{identifierKey}'])
    demisto.debug(
        f"Google BigQuery : * END * Performing get-modified-remote-data command. Results: {','.join(modified_records_ids)}")
    return GetModifiedRemoteDataResponse(modified_records_ids)


def get_remote_data_command(args):
    parsed_args = GetRemoteDataArgs(args)
    try:
        new_incident_data: Dict = get_data(parsed_args.remote_incident_id, parsed_args.last_update)
        remote_incident_id = new_incident_data[demisto.params()['identifierKey']]
        new_incident_data['id'] = remote_incident_id
        new_incident_data['in_mirror_error'] = ''
        return GetRemoteDataResponse(mirrored_object=new_incident_data, entries=[])
    except Exception as e:

        if new_incident_data:
            new_incident_data['in_mirror_error'] = str(e)
        else:
            new_incident_data = {
                'id': parsed_args.remote_incident_id,
                'in_mirror_error': str(e)
            }
        return GetRemoteDataResponse(
            mirrored_object=new_incident_data,
            entries=[]
        )


def fetch_incidents():
    identifierKey = demisto.params()['identifierKey']
    last_run = demisto.getLastRun()
    createdKey = demisto.params()['createdKey']
    first_fetch_time = demisto.params().get('firstFetchTime', '3 days').strip()
    demisto.debug(f'last_run: {last_run}' if last_run else 'last_run is empty')
    lastCreatedTime = last_run.get("lastFetch", parse(f'{first_fetch_time} UTC').isoformat().split("+")[0]).split(".")[0]
    newFetchTime = datetime.now().isoformat().split(".")[0]
    query = query_command({'query': FETCH_QUERY + f" AND {createdKey} > '{lastCreatedTime}'", 'incident': True})
    nextrun = {'lastFetch': newFetchTime}
    return nextrun, query, lastCreatedTime


def test_module():
    """
    Perform basic get request to get item samples
    """
    try:
        bigquery_client = start_and_return_bigquery_client(demisto.params()['google_service_creds'])
        query_job = bigquery_client.query(f'{FETCH_QUERY} LIMIT 1')
        query_results = query_job.result()
        demisto.results('ok')
    except Exception as ex:
        return_error("Authentication error: credentials JSON provided is invalid.\n Exception recieved:"
                     "{}".format(ex))


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'bigquery-query':
        query_command()
    elif demisto.command() == 'get-remote-data':
        return_results(get_remote_data_command(demisto.args()))
    elif demisto.command() == 'get-modified-remote-data':
        return_results(get_modified_remote_data_command(demisto.args()))
    elif demisto.command() == 'fetch-incidents':
        # Set and define the fetch incidents command to run after activated via integration settings.
        next_run, incidents, lastFetchTime = fetch_incidents()
        if len(incidents) == 0:
            next_run = {'lastFetch': lastFetchTime}
        demisto.setLastRun(next_run)
        demisto.incidents(incidents)


except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
