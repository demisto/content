import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *
''' IMPORTS '''
import requests
from requests.auth import HTTPBasicAuth
import urllib3


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
LIMIT = int(demisto.params().get('limit'))

USE_SSL = not demisto.params().get('unsecure', False)


# Service base URL
BASE_URL = "https://takedown.netcraft.com/"


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
TEST_MODULE_SUFFIX = "authorise-test.php"


# Table Headers
TAKEDOWN_INFO_HEADER = ["ID", "Status", "Attack Type", "Date Submitted", "Last Updated", "Reporter", "Group ID",
                        "Region", "Evidence URL", "Attack URL", "IP", "Domain", "Hostname", "Country Code",
                        "Domain Attack", "Targeted URL", "Certificate"]
TAKEDOWN_NOTE_HEADERS = ["Takedown ID", "Note ID", "Note", "Author", "Time", "Group ID"]

# Titles for human readables
TAKEDOWN_INFO_TITLE = "Takedowns information found:"
REPORT_MALICIOUS_SUCCESS_TITLE = "New takedown successfully created"


''' HELPER FUNCTIONS '''


@logger
def http_request(method, request_suffix, params=None, data=None, should_convert_to_json=True):
    # A wrapper for requests lib to send our requests and handle requests and responses better
    # the Netcraft API gets the arguments as params for GET requests, as data for POST
    res = requests.request(
        method,
        BASE_URL + request_suffix,
        verify=USE_SSL,
        params=params,
        data=data,
        auth=HTTPBasicAuth(USERNAME, PASSWORD)
    )

    if should_convert_to_json:
        return res.json()
    else:
        return res.text.splitlines()


@logger
def filter_by_id(result_list_to_filter, filtering_id_field, desired_id):
    """ Given a list of results, returns only the ones that are tied to a given ID.

    Args:
         result_list_to_filter (list): list of dictionaries, containing data about entries.
         filtering_id_field: The name of the field containing the IDs to filter.
         desired_id: The ID to keep when filtering.

    Returns:
        list: A copy of the input list, containing only entries with the desired ID.
    """

    new_results_list = [result for result in result_list_to_filter if result[filtering_id_field] == desired_id]
    return new_results_list


@logger
def generate_report_malicious_site_human_readable(response_lines_array):
    response_status_code = response_lines_array[0]
    human_readable = ""
    if response_status_code == MALICIOUS_REPORT_ALREADY_EXISTS:
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


@logger
def return_dict_without_none_values(dict_with_none_values):
    """ Removes all keys from given dict which have None as a value.

    Args:
        dict_with_none_values (dict): dict which may include keys with None as their value.

    Returns:
        dict: A new copy of the input dictionary, from which all keys with None as a value were removed.
    """
    new_dict = {key: dict_with_none_values[key] for key in dict_with_none_values if
                dict_with_none_values[key] is not None}
    return new_dict


@logger
def generate_takedown_info_context(takedown_info):
    takedown_info_context = {
        "ID": takedown_info.get("id"),
        "GroupID": takedown_info.get("group_id"),
        "Status": takedown_info.get("status"),
        "AttackType": takedown_info.get("attack_type"),
        "AttackURL": takedown_info.get("attack_url"),
        "Region": takedown_info.get("region"),
        "DateSubmitted": takedown_info.get("date_submitted"),
        "LastUpdated": takedown_info.get("last_updated"),
        "EvidenceURL": takedown_info.get("evidence_url"),
        "Reporter": takedown_info.get("reporter"),
        "IP": takedown_info.get("ip"),
        "Domain": takedown_info.get("domain"),
        "Hostname": takedown_info.get("hostname"),
        "CountryCode": takedown_info.get("country_code"),
        "DomainAttack": takedown_info.get("domain_attack"),
        "TargetedURL": takedown_info.get("targeted_url"),
        "Certificate": takedown_info.get("certificate")
    }

    return createContext(takedown_info_context, removeNull=True)


@logger
def gen_takedown_info_human_readable(list_of_takedowns_contexts, title=TAKEDOWN_INFO_TITLE):
    contexts_in_human_readable_format = []
    for takedown_info_context in list_of_takedowns_contexts:
        human_readable_dict = {
            "ID": takedown_info_context.get("ID"),
            "Status": takedown_info_context.get("Status"),
            "Attack Type": takedown_info_context.get("AttackType"),
            "Date Submitted": takedown_info_context.get("DateSubmitted"),
            "Last Updated": takedown_info_context.get("LastUpdated"),
            "Reporter": takedown_info_context.get("Reporter"),
            "Group ID": takedown_info_context.get("GroupID"),
            "Region": takedown_info_context.get("Region"),
            "Evidence URL": takedown_info_context.get("EvidenceURL"),
            "Attack URL": takedown_info_context.get("AttackURL"),
            "IP": takedown_info_context.get("IP"),
            "Domain": takedown_info_context.get("Domain"),
            "Hostname": takedown_info_context.get("Hostname"),
            "Country Code": takedown_info_context.get("CountryCode"),
            "Domain Attack": takedown_info_context.get("DomainAttack"),
            "Targeted URL": takedown_info_context.get("TargetedURL"),
            "Certificate": takedown_info_context.get("Certificate")
        }
        contexts_in_human_readable_format.append(human_readable_dict)

    human_readable = tableToMarkdown(title, contexts_in_human_readable_format,
                                     headers=TAKEDOWN_INFO_HEADER, removeNull=True)
    return human_readable


@logger
def generate_list_of_takedowns_context(list_of_takedowns_infos):
    takedowns_contexts_list = []
    for takedown_info in list_of_takedowns_infos:
        takedown_context = generate_takedown_info_context(takedown_info)
        takedowns_contexts_list.append(takedown_context)
    return takedowns_contexts_list


@logger
def generate_takedown_note_context(takedown_note_json):
    takedown_note_context = {
        "TakedownID": takedown_note_json.get("takedown_id"),
        "NoteID": takedown_note_json.get("note_id"),
        "GroupID": takedown_note_json.get("group_id"),
        "Author": takedown_note_json.get("author"),
        "Note": takedown_note_json.get("note"),
        "Time": takedown_note_json.get("time")
    }
    takedown_note_context = return_dict_without_none_values(takedown_note_context)
    return takedown_note_context


@logger
def generate_list_of_takedown_notes_contexts(list_of_takedowns_notes):
    takedown_notes_contexts_list = []
    for takedown_note in list_of_takedowns_notes:
        takedown_note_context = generate_takedown_note_context(takedown_note)
        takedown_notes_contexts_list.append(takedown_note_context)
    return takedown_notes_contexts_list


@logger
def gen_takedown_notes_human_readable(entry_context):
    contexts_in_human_readable_format = []
    for takedown_note_context in entry_context:
        human_readable_dict = {
            "Takedown ID": takedown_note_context.get("TakedownID"),
            "Note ID": takedown_note_context.get("NoteID"),
            "Group ID": takedown_note_context.get("GroupID"),
            "Author": takedown_note_context.get("Author"),
            "Note": takedown_note_context.get("Note"),
            "Time": takedown_note_context.get("Time")
        }
        human_readable_dict = return_dict_without_none_values(human_readable_dict)
        contexts_in_human_readable_format.append(human_readable_dict)

    human_readable = tableToMarkdown(TAKEDOWN_INFO_TITLE, contexts_in_human_readable_format,
                                     headers=TAKEDOWN_NOTE_HEADERS)
    return human_readable


@logger
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


@logger
def string_to_bool(string_representing_bool):
    return string_representing_bool.lower() == "true"


@logger
def generate_escalate_takedown_human_readable(response):
    if "status" in response:
        human_readable = "### Takedown escalated successfully"
    else:
        human_readable = "### Takedown escalation failed\n" \
                         "An error occured on the takedown escalation attempt.\n" \
                         "Error code is: {0}\n" \
                         "Error message from Netcraft is: {1}".format(response["error_code"], response["error_message"])
    return human_readable


def add_or_update_note_context_in_takedown(note_context, cur_notes_in_takedown):
    if isinstance(cur_notes_in_takedown, dict):
        return [note_context]
    else:
        note_already_in_context = False
        for i, cur_note_context in enumerate(cur_notes_in_takedown):
            cur_note_context = cur_notes_in_takedown[i]
            if cur_note_context["NoteID"] == note_context["NoteID"]:
                note_already_in_context = True
                cur_notes_in_takedown[i] = note_context
        if not note_already_in_context:
            cur_notes_in_takedown.append(note_context)
        return cur_notes_in_takedown


def add_note_to_suitable_takedown_in_context(note_context, all_takedowns_entry_context):
    note_takedown_index = -1
    if isinstance(all_takedowns_entry_context, dict):
        new_takedown_entry_context = {
            "ID": note_context["TakedownID"],
            "Note": [note_context]
        }
        all_takedowns_entry_context = [all_takedowns_entry_context, new_takedown_entry_context] \
            if all_takedowns_entry_context else [new_takedown_entry_context]
    else:
        for i in range(len(all_takedowns_entry_context)):
            cur_takedown_context = all_takedowns_entry_context[i]
            if cur_takedown_context["ID"] == note_context["TakedownID"]:
                note_takedown_index = i
        if note_takedown_index == -1:
            new_takedown_entry_context = {
                "ID": note_context["TakedownID"],
                "Note": [note_context]
            }
            all_takedowns_entry_context.append(new_takedown_entry_context)
        else:
            takedown_context_to_change = all_takedowns_entry_context[note_takedown_index]
            cur_notes_in_takedown = takedown_context_to_change["Note"]
            takedown_context_to_change["Note"] = add_or_update_note_context_in_takedown(note_context,
                                                                                        cur_notes_in_takedown)
            all_takedowns_entry_context[note_takedown_index] = takedown_context_to_change
    return all_takedowns_entry_context


def generate_netcraft_context_with_notes(list_of_notes_contexts):
    all_takedowns_entry_context = demisto.context().get("Netcraft", {}).get("Takedown", {})
    for note_context in list_of_notes_contexts:
        all_takedowns_entry_context = add_note_to_suitable_takedown_in_context(note_context,
                                                                               all_takedowns_entry_context)
    return all_takedowns_entry_context


''' COMMANDS + REQUESTS FUNCTIONS '''


@logger
def escalate_takedown(takedown_id):
    data_for_request = {
        "takedown_id": takedown_id
    }
    request_result = http_request("POST", ESCALATE_TAKEDOWN_SUFFIX, data=data_for_request)
    return request_result


def escalate_takedown_command():
    args = demisto.args()
    response = escalate_takedown(args["takedown_id"])
    human_readable = generate_escalate_takedown_human_readable(response)
    return_outputs(
        readable_output=human_readable,
        outputs={},
        raw_response=response
    )


@logger
def add_notes_to_takedown(takedown_id, note, notify):
    data_for_request = {
        "takedown_id": takedown_id,
        "note": note,
        "notify": notify
    }

    data_for_request = return_dict_without_none_values(data_for_request)

    request_result = http_request("POST", ACCESS_TAKEDOWN_NOTES_SUFFIX, data=data_for_request)
    return request_result


def add_notes_to_takedown_command():
    args = demisto.args()
    note = args.get("note")
    notify = string_to_bool(args.get("notify")) if args.get("notify") else None
    takedown_id = int(args["takedown_id"])
    response = add_notes_to_takedown(takedown_id, note, notify)
    human_readable = generate_add_note_human_readable(response)
    return_outputs(
        readable_output=human_readable,
        outputs=response
    )


def get_takedown_notes(takedown_id, group_id, date_from, date_to, author):
    params_for_request = {
        "takedown_id": takedown_id,
        "group_id": group_id,
        "date_to": date_to,
        "date_from": date_from,
        "author": author
    }

    params_for_request = return_dict_without_none_values(params_for_request)

    request_result = http_request("GET", ACCESS_TAKEDOWN_NOTES_SUFFIX, params=params_for_request)
    return request_result


def get_takedown_notes_command():
    args = demisto.args()
    takedown_id = int(args.get("takedown_id")) if args.get("takedown_id") else None
    group_id = int(args.get("group_id")) if args.get("group_id") else None
    date_from = args.get("date_from")
    date_to = args.get("date_to")
    author = args.get("author")
    list_of_takedowns_notes = get_takedown_notes(takedown_id, group_id, date_from, date_to, author)
    list_of_takedowns_notes = list_of_takedowns_notes[:LIMIT]
    if takedown_id:
        list_of_takedowns_notes = filter_by_id(list_of_takedowns_notes, "takedown_id", int(takedown_id))
    list_of_notes_contexts = generate_list_of_takedown_notes_contexts(list_of_takedowns_notes)
    entry_context = {
        "Netcraft.Takedown(val.ID == obj.ID)": generate_netcraft_context_with_notes(list_of_notes_contexts)
    }
    human_readable = gen_takedown_notes_human_readable(list_of_notes_contexts)
    return_outputs(
        readable_output=human_readable,
        outputs=entry_context,
        raw_response=list_of_takedowns_notes
    )


@logger
def get_takedown_info(takedown_id, ip, url, updated_since, date_from, region):
    params_for_request = {
        "id": takedown_id,
        "ip": ip,
        "url": url,
        "updated_since": updated_since,
        "date_from": date_from,
        "region": region,
    }

    params_for_request = return_dict_without_none_values(params_for_request)

    request_result = http_request("GET", GET_TAKEDOWN_INFO_SUFFIX, params=params_for_request)
    return request_result


def get_takedown_info_command():
    args = demisto.args()
    takedown_id = int(args.get("id")) if args.get("id") else None
    ip = args.get("ip")
    url = args.get("url")
    updated_since = args.get("updated_since")
    date_from = args.get("date_from")
    region = args.get("region")
    list_of_takedowns_infos = get_takedown_info(takedown_id, ip, url, updated_since, date_from, region)
    list_of_takedowns_infos = list_of_takedowns_infos[:LIMIT]
    if takedown_id:
        list_of_takedowns_infos = filter_by_id(list_of_takedowns_infos, "id", str(takedown_id))
    list_of_takedowns_contexts = generate_list_of_takedowns_context(list_of_takedowns_infos)
    human_readable = gen_takedown_info_human_readable(list_of_takedowns_contexts)
    entry_context = {
        'Netcraft.Takedown(val.ID == obj.ID)': list_of_takedowns_contexts
    }
    return_outputs(
        readable_output=human_readable,
        raw_response=list_of_takedowns_infos,
        outputs=entry_context,
    )


@logger
def report_attack(malicious_site_url, comment, is_test_request=False):
    data_for_request = {
        "attack": malicious_site_url,
        "comment": comment
    }
    if is_test_request:
        request_url_suffix = TEST_MODULE_SUFFIX
    else:
        request_url_suffix = REPORT_MALICIOUS_SUFFIX
    request_result = http_request("POST", request_url_suffix, data=data_for_request, should_convert_to_json=False)
    return request_result


def report_attack_command():
    args = demisto.args()
    entry_context: dict = {}
    response_lines_array = report_attack(args["attack"], args["comment"])
    result_answer = response_lines_array[0]
    if result_answer == MALICIOUS_REPORT_SUCCESS:
        new_takedown_id = response_lines_array[1]
        # Until the API bug is fixed, this list will include info of all takedowns and not just the new one
        new_takedown_infos = get_takedown_info(new_takedown_id, None, None, None, None, None)
        new_takedown_infos = new_takedown_infos[:LIMIT]
        new_takedown_infos = filter_by_id(new_takedown_infos, "id", new_takedown_id)
        list_of_new_takedown_contexts = generate_list_of_takedowns_context(new_takedown_infos)
        human_readable = gen_takedown_info_human_readable(list_of_new_takedown_contexts, REPORT_MALICIOUS_SUCCESS_TITLE)
        entry_context = {
            'Netcraft.Takedown(val.ID == obj.ID)': list_of_new_takedown_contexts
        }
    else:
        human_readable = generate_report_malicious_site_human_readable(response_lines_array)

    return_outputs(
        readable_output=human_readable,
        outputs=entry_context,
        raw_response=entry_context
    )


def test_module():
    """
    Performs basic get request to get item samples
    """
    test_result = report_attack("https://www.test.com", "test", True)
    if test_result[0] != MALICIOUS_REPORT_SUCCESS:
        raise Exception("Test request failed.")
    demisto.results("ok")


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    # Remove proxy if not set to true in params
    handle_proxy()
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'netcraft-report-attack':
        report_attack_command()
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
    return_error(str(e))
