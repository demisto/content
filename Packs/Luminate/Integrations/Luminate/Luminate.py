import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import ast
from datetime import datetime
import json
import time

import dateparser
from luminateapi.luminate_python import LuminateV2Client

''' CONSTS '''
DEFAULT_FETCH_SIZE = 10
VERIFY_CERTIFICATE = True
MAX_ALERTS_FETCH = 500

''' FUNCTIONS '''
''' HELPER FUNCTIONS '''


def human_readable_string_to_epoch(data):
    return int(dateparser.parse(data).strftime('%s')) * 1000


def make_table_header(header):
    return header.replace("@", "").replace("_", " ").title()


def format_logs_output(data, context_path):
    lines = [x['Data'] for x in data['Logs']]

    md = tableToMarkdown('Access Logs', lines, headerTransform=make_table_header)

    return {
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            context_path: data
        }
    }


def format_bulk_result(result, context_path):
    res = []
    for status, idps in result.iteritems():
        for k, v in idps.iteritems():
            lines = [{"User": x} for x in v]
            md = tableToMarkdown("{} {}".format(k.title(), status.title()), lines, ["User"])
            res.append({
                'Type': entryTypes['note'],
                'Contents': result,
                'ContentsFormat': formats['json'],
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': {
                    context_path: result
                }
            })

    return res


def get_http_access_logs_command():
    args = demisto.args()

    query = {}
    if "free_text" in args:
        query["free_text"] = args["free_text"]
    if "from_date" in args:
        query["from_date"] = human_readable_string_to_epoch(args["from_date"])
    if "to_date" in args:
        query["to_date"] = human_readable_string_to_epoch(args["to_date"])

    search_after = None
    if "search_after" in args:
        search_after = ast.literal_eval(args["search_after"])

    size = int(args.get("size", DEFAULT_FETCH_SIZE))

    result = luminate_client.get_access_logs(size, query, search_after)

    return format_logs_output(result, "Luminate.AccessLogs")


def get_ssh_access_logs_command():
    args = demisto.args()

    query = {}
    if "free_text" in args:
        query["free_text"] = args["free_text"]
    if "from_date" in args:
        query["from_date"] = human_readable_string_to_epoch(args["from_date"])
    if "to_date" in args:
        query["to_date"] = human_readable_string_to_epoch(args["to_date"])

    search_after = None
    if "search_after" in args:
        search_after = ast.literal_eval(args["search_after"])

    size = int(args.get("size", DEFAULT_FETCH_SIZE))

    result = luminate_client.get_ssh_access_logs(size, query, search_after)

    return format_logs_output(result, "Luminate.SshAccessLogs")


def block_user_by_email_command():
    args = demisto.args()
    user_email = args.get('user_email', "")

    result = luminate_client.block_user_by_email(user_email)

    return format_bulk_result(result, "Luminate.Blocked")


def unblock_user_by_email_command():
    args = demisto.args()
    user_email = args.get('user_email', "")

    result = luminate_client.unblock_user_by_email(user_email)

    return format_bulk_result(result, "Luminate.Unblocked")


def destroy_user_sessions_by_email_command():
    args = demisto.args()
    user_email = args.get('user_email', "")

    result = luminate_client.destroy_user_sessions_by_email(user_email)

    return format_bulk_result(result, "Luminate.DestroySession")


def alert_to_incident(line):

    data = line.get("Data")
    if not data:
        raise Exception("no data")

    tenant, rule_name, rule_severity = data.get('rule_name').split("##")[:3]
    alert_time = data.get('alert_time', datetime.now().isoformat())

    return {
        'type': 'Luminate',
        'name': rule_name,
        'occurred': alert_time.split(".")[0] + "Z",
        'severity': severity_to_level(rule_severity),
        'rawJSON': json.dumps(data),
    }


def severity_to_level(severity):
    if severity.lower() == "high":
        return 3
    elif severity.lower() == "medium":
        return 2
    else:
        return 1


def fetch_incidents():
    last_run = demisto.getLastRun()
    last_fetch = last_run.get('time')

    # handle first time fetch
    if last_fetch is None:
        last_fetch = human_readable_string_to_epoch("5 days ago")
    current_fetch = last_fetch

    query = {"from_date": current_fetch}
    result = luminate_client.get_alerts(MAX_ALERTS_FETCH, query, None)

    incidents = []
    # in case there is no alerts we move the last time to now.
    temp_date = int(time.time() * 1000)
    for data in result.get('Logs', []):
        incident = alert_to_incident(data)
        temp_date = human_readable_string_to_epoch(incident['occurred']) + 1000

        incidents.append(incident)

    demisto.setLastRun({'time': temp_date})

    return incidents


''' EXECUTION CODE '''
LOG('command is {}'.format(demisto.command()))

try:
    luminate_client = LuminateV2Client(demisto.params()['luminate_api_url'],
                                       demisto.params()['api_key'],
                                       demisto.params()['api_secret'],
                                       VERIFY_CERTIFICATE)

    if demisto.command() == 'test-module':
        demisto.results('ok')
        sys.exit(0)

    if demisto.command() == 'fetch-incidents':
        demisto.incidents(fetch_incidents())
        sys.exit(0)

    if demisto.command() == 'lum-block-user':
        demisto.results(block_user_by_email_command())
    elif demisto.command() == 'lum-unblock-user':
        demisto.results(unblock_user_by_email_command())
    elif demisto.command() == 'lum-destroy-user-session':
        demisto.results(destroy_user_sessions_by_email_command())
    elif demisto.command() == 'lum-get-http-access-logs':
        demisto.results(get_http_access_logs_command())
    elif demisto.command() == 'lum-get-ssh-access-logs':
        demisto.results(get_ssh_access_logs_command())

except Exception, e:
    LOG('{}: {}'.format(type(e), e.message))
    if demisto.command() != 'test-module':
        LOG.print_log()

    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': 'error has occured: %s' % (e.message,),
    })
