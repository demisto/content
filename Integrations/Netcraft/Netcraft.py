
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
from base64 import b64encode
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params().get('username')
PASSWORD = demisto.params().get('password')
USERNAME_AND_PASSWORD_ENCODED = b64encode("{0}:{1}".format(USERNAME,PASSWORD)) #should maybe add .decode("ascii")
HEADERS = {
    'Authorization': "Base {}".format(USERNAME_AND_PASSWORD_ENCODED)
}

USE_SSL = not demisto.params().get('unsecure', False)


# Service base URL
BASE_URL = "https://takedown.netcraft.com/" # should be parameter? or hard coded like this?


# codes for maicious site report
MALICIOUS_REPORT_SUCCESS = "TD_OK"
MALICIOUS_REPORT_ALREADY_EXISTS = "TD_EXISTS"
MALICIOUS_REPORT_URL_IS_WILDCARD = "TD_WILDCARD"
MALICIOUS_REPORT_ACCESS_DENIED = "TD_DENIED"
MALICIOUS_REPORT_ERROR = "TD_ERROR"


# suffix endpoints
REPORT_MALICIOUS_SUFFIX = "authorise.php"
GET_TAKEDOWN_INFO_SUFFIX = "apis/get-info.php"
ACCESS_TAKEDOWN_NOTES_SUFFIX = "apis/note.php"
ESCALATE_TAKEDOWN_SUFFIX = "apis/escalate.php"


# Table Headers
TAKEDOWN_INFO_HEADER = ["ID", "Status", "Attack Type", "Date Submitted", "Last Updated", "Reporter", "Group ID",
                        "Region", "Evidence URL", "Attack URL", "IP", "Domain", "Hostname", "Country Code", "Domain Attack",
                        "Targeted URL", "Certificate"]

# Titles for human readables
TAKEDOWN_INFO_TITLE = "Takedowns information found"



# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def http_request(method, request_url, params=None, data=None, should_convert_to_json = True):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        request_url,
        verify=USE_SSL,
        params=params,
        data=data,
        headers=HEADERS
    )
    # Handle error responses gracefully
    if res.status_code not in {200}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

    if should_convert_to_json:
        return res.json()
    else:
        # not sure this will work, the answer should be plain text but could be a file
        return res.text.splitlines()



def generate_report_malicious_site_human_readable(response_lines_array):
    response_status_code = response_lines_array[0]
    human_readable = ""
    if response_status_code == MALICIOUS_REPORT_SUCCESS:
        human_readable = "### Takedown successfully submitted \n ID number of the new takedown: {}.".format(response_lines_array[1])
    elif response_status_code == MALICIOUS_REPORT_ALREADY_EXISTS:
        human_readable = "### Takedown not submitted.\n " \
                         "A takedown for this URL already exists.\n" \
                         "ID number of the existing takedown: {}.".format(response_lines_array[1])
    elif response_status_code == MALICIOUS_REPORT_URL_IS_WILDCARD:
        human_readable = "### Takedown not submitted\n " \
                         "This URL is a wildcard sub-domain variation of an existing takedown.\n"
    elif response_status_code == MALICIOUS_REPORT_ACCESS_DENIED:
        human_readable = "### Takedown not submitted\n Access is denied."
    elif response_status_code == MALICIOUS_REPORT_ERROR:
        human_readable = "### Takedown not submitted\n " \
                         "An error has occurred while submitting your takedown.\n" \
                         "Error is: {}".format(" ".join(response_lines_array))
    return human_readable




def return_dict_without_none_values(dict_with_none_values):
    new_dict = {key: dict_with_none_values[key] for key in dict_with_none_values if dict_with_none_values[key]}
    return new_dict


def generate_takedown_info_context(takedown_info):
    takedown_info_context = {
        "ID": takedown_info.get("id", None),
        "GroupID": takedown_info.get("group_id", None),
        "Status": takedown_info.get("status", None),
        "AttackType": takedown_info.get("attack_type", None),
        "AttackURL": takedown_info.get("attack_url", None),
        "Region": takedown_info.get("region", None),
        "DateSubmitted": takedown_info.get("date_submitted", None),
        "LastUpdated": takedown_info.get("last_updated", None),
        "EvidenceURL": takedown_info.get("evidence_url", None),
        "Reporter": takedown_info.get("reporter", None),
        "IP": takedown_info.get("ip", None),
        "Domain": takedown_info.get("domain", None),
        "Hostname": takedown_info.get("hostname", None),
        "CountryCode": takedown_info.get("country_code", None),
        "DomainAttack": takedown_info.get("domain_attack", None),
        "TargetedURL": takedown_info.get("targeted_url", None),
        "Certificate": takedown_info.get("certificate", None)
    }

    # remove nulls from dict
    takedown_info_context = return_dict_without_none_values(takedown_info_context)
    return takedown_info_context



def gen_takedown_info_human_readable(entry_context):
    contexts_in_human_readable_format = []
    for takedown_info_context in entry_context:
        human_readable_dict = {
            "ID": takedown_info_context.get("ID", None),
            "Status": takedown_info_context.get("Status", None),
            "Attack Type": takedown_info_context.get("AttackType", None),
            "Date Submitted": takedown_info_context.get("DateSubmitted", None),
            "Last Updated": takedown_info_context.get("LastUpdated", None),
            "Reporter": takedown_info_context.get("Reporter", None),
            "Group ID": takedown_info_context.get("GroupID", None),
            "Region": takedown_info_context.get("Region", None),
            "Evidence URL": takedown_info_context.get("EvidenceURL", None),
            "Attack URL": takedown_info_context.get("AttackURL", None),
            "IP": takedown_info_context.get("IP", None),
            "Domain": takedown_info_context.get("Domain", None),
            "Hostname": takedown_info_context.get("Hostname", None),
            "Country Code": takedown_info_context.get("CountryCode", None),
            "Domain Attack": takedown_info_context.get("DomainAttack", None),
            "Targeted URL": takedown_info_context.get("TargetedURL", None),
            "Certificate": takedown_info_context.get("Certificate", None)
        }
        human_readable_dict = return_dict_without_none_values(human_readable_dict)
        contexts_in_human_readable_format.append(human_readable_dict)

    human_readable = tableToMarkdown(TAKEDOWN_INFO_TITLE, human_readable_dict, headers=TAKEDOWN_INFO_HEADER)
    return human_readable


def generate_list_of_takedowns_context(list_of_takedowns_infos):
    takedowns_contexts_list = []
    for takedown_info in list_of_takedowns_infos:
        takedown_context = generate_takedown_info_context(takedown_info)
        takedowns_contexts_list.append(takedown_context)
    return takedowns_contexts_list



def generate_takedown_note_context(takedown_note_json):
    takedown_note_context = {
        "TakedownID": takedown_note_json.get("takedown_id", None),
        "NoteID": takedown_note_json.get("note_id", None),
        "GroupID": takedown_note_json.get("group_id", None),
        "Author": takedown_note_json.get("author", None),
        "Note": takedown_note_json.get("note", None),
        "Time": takedown_note_json.get("time", None)
    }
    takedown_note_context = return_dict_without_none_values(takedown_note_context)
    return takedown_note_context


def generate_list_of_takedown_notes_contexts(list_of_takedowns_notes):
    takedown_notes_contexts_list = []
    for takedown_note in list_of_takedowns_notes:
        takedown_note_context = generate_takedown_note_context(takedown_note)
        takedown_notes_contexts_list.append(takedown_note_context)
    return takedown_notes_contexts_list


def gen_takedown_notes_human_readable(entry_context):
    contexts_in_human_readable_format = []
    for takedown_note_context in entry_context:
        human_readable_dict = {
            "Takedown ID": takedown_note_context.get("TakedownID", None),
            "Note ID": takedown_note_context.get("NoteID", None),
            "Group ID": takedown_note_context.get("GroupID", None),
            "Author": takedown_note_context.get("Author", None),
            "Note": takedown_note_context.get("Note", None),
            "Time": takedown_note_context.get("Time", None)
        }
        human_readable_dict = return_dict_without_none_values(human_readable_dict)
        contexts_in_human_readable_format.append(human_readable_dict)

    human_readable = tableToMarkdown(TAKEDOWN_INFO_TITLE, human_readable_dict, headers=TAKEDOWN_INFO_HEADER)
    return human_readable


def generate_add_note_human_readable(response):
    # if the request was successful, the response includes the id of the created note
    if "note_id" in response:
        human_readable = "### Note added succesfully\n" \
                         "ID of the note created: {0}".format(response["note_id"])
    else:
        human_readable = "### Failed to add note\n" \
                         "An error occured while trying to add the note.\n" \
                         "The error code is: {0}.\n" \
                         "The error message is: {1}.".format(response["error_code"], response["error_code"])
    return human_readable




def string_to_bool(string_representing_bool):
    return string_representing_bool.lower() == "true"


def generate_escalate_takedown_human_readable(response):
    if "status" in response:
        human_readable = "### Takedown escalated successfully"
    else:
        human_readable = "### Takedown escalation failed\n" \
                         "An error occured on the takedown escalation attempt.\n" \
                         "Error code is: {0}\n" \
                         "Error message from Netcraft is: {1}".format(response["error_code"], response["error_message"])
    return human_readable


''' COMMANDS + REQUESTS FUNCTIONS '''


def escalate_takedown(takedown_id):
    data_for_request = {
        "takedown_id": takedown_id
    }
    request_url = BASE_URL + ESCALATE_TAKEDOWN_SUFFIX
    request_result = http_request("POST", request_url, data=data_for_request)
    return request_result



def escalate_takedown_command():
    args = demisto.args()
    response = escalate_takedown(args["takedown_id"])
    human_readable = generate_escalate_takedown_human_readable(response)
    return_outputs(
        readable_output=human_readable,
        outputs=response
    )












def add_notes_to_takedown(takedown_id, note, notify):
    data_for_request = {
        "takedown_id": takedown_id,
        "note": note,
        "notify": string_to_bool(notify)
    }
    # removing keys with None as value
    data_for_request = return_dict_without_none_values(data_for_request)

    request_url = BASE_URL + ACCESS_TAKEDOWN_NOTES_SUFFIX
    request_result = http_request("POST", request_url, data=data_for_request)
    return request_result


def add_notes_to_takedown_command():
    args = demisto.args()
    note = args.get("note", None)
    notify = args.get("notify", None)
    takedown_id = args.get("takedown_id", None)
    response = add_notes_to_takedown(takedown_id, note, notify)
    human_readable = generate_add_note_human_readable(response)
    return_outputs(
        readable_output=human_readable,
        outputs=response
    )


def get_takedown_notes(takedown_id, group_id, date_from, date_to, author):
    data_for_request = {
        "takedown_id": takedown_id,
        "group_id": group_id,
        "date_to": date_to,
        "date_from": date_from,
        "author": author
    }

    data_for_request = return_dict_without_none_values(data_for_request)

    request_url = BASE_URL + ACCESS_TAKEDOWN_NOTES_SUFFIX
    request_result = http_request("GET", request_url, data=data_for_request)
    return request_result


def get_takedown_notes_command():
    args = demisto.args()
    takedown_id = args.get("takedown_id", None)
    group_id = args.get("group_id", None)
    date_from = args.get("date_from", None)
    date_to = args.get("date_to", None)
    author = args.get("author", None)
    list_of_takedowns_notes = get_takedown_notes(takedown_id, group_id, date_from, date_to, author)
    entry_context = generate_list_of_takedown_notes_contexts(list_of_takedowns_notes)
    human_readable = gen_takedown_notes_human_readable(entry_context)
    return_outputs(
        readable_output=human_readable,
        outputs=entry_context,
        raw_response=list_of_takedowns_notes
    )


def get_takedown_info(id, ip, url, updated_since, date_from, region):
    data_for_request = {
        "id": id,
        "ip": ip,
        "url": url,
        "updated_since": updated_since,
        "date_from": date_from,
        "region": region,
    }
    # removing keys with None as value
    data_for_request = return_dict_without_none_values(data_for_request)

    request_url = BASE_URL + GET_TAKEDOWN_INFO_SUFFIX
    request_result = http_request("GET", request_url, data=data_for_request)
    return request_result



def get_takedown_info_command():
    args = demisto.args()
    id = args.get("id", None)
    ip = args.get("ip", None)
    url = args.get("url", None)
    updated_since = args.get("updated_since", None)
    date_from = args.get("date_from", None)
    region = args.get("region", None)
    list_of_takedowns_infos = get_takedown_info(id, ip, url, updated_since, date_from, region)
    entry_context = generate_list_of_takedowns_context(list_of_takedowns_infos)
    human_readable = gen_takedown_info_human_readable(entry_context)
    return_outputs(
        readable_output=human_readable,
        outputs=entry_context,
        raw_response=list_of_takedowns_infos
    )



def report_malicious_site(malicious_site_url, comment):
    data_for_request = {
        "attack": malicious_site_url,
        "comment": comment
    }
    request_url = BASE_URL + REPORT_MALICIOUS_SUFFIX
    request_result = http_request("POST", request_url, data = data_for_request, should_convert_to_json=False)
    return request_result



def report_malicious_site_command():
    args = demisto.args()
    entry_context = None
    response_lines_array = report_malicious_site(args["malicious_site_url"], args["comment"]) #not sure this line works
    result_answer = response_lines_array[0]
    if result_answer == MALICIOUS_REPORT_SUCCESS:
        new_takedown_id = response_lines_array[1]
        entry_context = {
            "TakedownID": new_takedown_id
        }

    human_readable = generate_report_malicious_site_human_readable(response_lines_array)

    return_outputs(
        readable_output=human_readable,
        outputs='\n'.join(response_lines_array),
        raw_response=entry_context
    )




def test_module():
    """
    Performs basic get request to get item samples
    """
    samples = http_request('GET', 'items/samples')




''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'netcraft-report-malicious-site':
        report_malicious_site_command()
    elif demisto.command() == 'netcraft-get-takedown-info':
        get_takedown_info_command()
    elif demisto.command() == 'netcraft-get-takedown-notes':
        get_takedown_notes_command()
    elif demisto.command() == 'netcraft-add-notes-to-takedown':
        add_notes_to_takedown_command()
    elif demisto.command() == 'netcraft-escalate-takedown':
        escalate_takedown_command()


# Log exceptions
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
