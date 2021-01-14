import json
import traceback
from typing import Any, Dict, Optional

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_policy(self, policy_id: Optional[str] = None) -> Dict[str, Any]:
        if policy_id:
            return self._http_request(
                method='GET',
                url_suffix='/policy/{}'.format(policy_id))
        else:
            return self._http_request(
                method='GET',
                url_suffix='/policy')

    def set_policy(self, policy_id: str, update_method: str, policy_json: Dict[str, Any]) -> Dict[str, Any]:
        update_method = update_method.upper()
        return self._http_request(
            method=update_method,
            url_suffix='/policy/{}'.format(policy_id),
            json_data=policy_json)

    def search_events(self, args: Optional[dict]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/search/events',
            json_data=args)

    def remediate_message(self, action: str, action_args: Optional[dict]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/remediation/{}'.format(action),
            json_data=action_args)

    def revert_remediate_message(self, action: str, action_args: Optional[dict]) -> Dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/remediation/revert/{}'.format(action),
            json_data=action_args)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: GreatHorn client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_policy()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            raise 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def gh_search_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    fields = argToList(args.get('fields'))
    limit = args.get('limit')
    sort = args.get('sort')
    sortDir = args.get('sortDir')
    offset = args.get('offset')
    filters = json.loads(args.get('filters', "[]"))

    args = {"filters": filters}
    if fields is not None and len(fields) > 0:
        if "eventId" not in fields:
            fields.append("eventId")
        args['fields'] = fields
    if limit is not None:
        args['limit'] = limit
    if offset is not None:
        args['offset'] = offset
    if sort is not None:
        args['sort'] = sort
    if sortDir is not None:
        args['sortDir'] = sortDir

    results = client.search_events(args)
    events = []

    if fields is None or len(fields) == 0:
        for event in results.get("results", []):
            e = {
                "ID": event.get("eventId"),
                "From Address": event.get("source"),
                "Mailbox": event.get("origin"),
                "Return Path": event.get("sourcePath"),
                "Subject": event.get("subject"),
                "Occurred": event.get("timestamp")
            }

            policy_names = []
            policy_actions = []
            if event.get("flag") is not None:
                for policy_id in event.get("flag", []):
                    policy = client.get_policy(policy_id).get("policy", {})
                    actions = []
                    for action in policy.get("actions"):
                        actions.append(action.get("type"))
                    policy_names.append(policy.get("name"))
                    policy_actions.extend(actions)

                e['Policy Hits'] = policy_names
                e['Policy Actions'] = policy_actions
            if len(event.get('files', [])) > 0:
                e['Has Attachments'] = True
            else:
                e['Has Attachments'] = False
            if len(event.get('links', [])) > 0:
                e['Has Links'] = True
            else:
                e['Has Links'] = False

            events.append(e)

        events_md = tableToMarkdown("Events", events, ["ID", "From Address", "Mailbox", "Return Path",
                                                       "Subject", "Policy Hits", "Policy Actions",
                                                       "Occurred", "Has Attachments", "Has Links"])
    else:
        events_md = tableToMarkdown("Events", results.get("results", []), fields)

    result = {'Message': results.get("results"), 'SearchCount': results.get("total")}

    return CommandResults(
        readable_output=events_md,
        outputs_prefix='GreatHorn',
        outputs_key_field='eventId',
        outputs=result
    )


def gh_revert_remediate_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    valid_actions: Dict[str, list] = {"banner": [],
                                      "quarantinerequest": [],
                                      "quarantinerelease": [],
                                      "quarantinedeny": [],
                                      "removeattachments": [],
                                      "review": []
                                      }
    if args.get('action', "").lower() not in valid_actions.keys():
        raise ValueError('Invalid action "{}" specified'.format(args.get('action')))
    action = args.get('action', "").lower()
    for arg in valid_actions.get(action, []):
        if args.get(arg) is None:
            raise ValueError('Revert action "{}" requires argument "{}" to be specified'.format(action, arg))

    del args['action']
    if action == "quarantinerequest":
        action = "quarantine/request"
    if action == "quarantinerelease":
        action = "quarantine"
    if action == "quarantinedeny":
        action = "quarantine/deny"

    results = client.revert_remediate_message(action, args)
    if results.get("success") is True:
        human_readable = "Revert action {} applied successfully to message {}".format(action, args.get("eventId"))
    else:
        if results.get("reason") == "alreadyDone":
            human_readable = "Revert action {} has already been performed on message {}".format(action, args.get("eventId"))
    results['action'] = action
    results['eventId'] = args.get('eventId')

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='GreatHorn.Remediation',
        outputs_key_field='eventId',
        outputs=results
    )


def gh_remediate_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    valid_actions: Dict[str, list] = {"archive": [],
                                      "banner": ["hasButton", "message"],
                                      "delete": [],
                                      "label": ["label"],
                                      "move": ["location"],
                                      "quarantine": [],
                                      "removeattachments": [],
                                      "review": [],
                                      "trash": []
                                      }
    if args.get('action', "").lower() not in valid_actions.keys():
        raise ValueError('Invalid action "{}" specified'.format(args.get('action')))
    action = args.get('action', "").lower()
    for arg in valid_actions.get(action, []):
        if args.get(arg) is None:
            raise ValueError('Remediate action "{}" requires argument "{}" to be specified'.format(action, arg))

    del args['action']
    if action != "banner":
        args.pop('hasButton', None)

    results = client.remediate_message(action, args)
    if results.get("success") is True:
        human_readable = "Remediate action {} applied successfully to message {}".format(action, args.get("eventId"))
    else:
        if results.get("reason") == "alreadyDone":
            human_readable = "Remediate action {} has already been performed on message {}".format(action, args.get("eventId"))
    results['action'] = action
    results['eventId'] = args.get('eventId')

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='GreatHorn.Remediation',
        outputs_key_field='eventId',
        outputs=results
    )


def gh_set_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    update_method = args.get('updatemethod', "").lower()
    policy_id = args.get('policiyid', "")
    policy_json = json.loads(args.get('policyjson', {}))
    if update_method not in ['patch', 'put']:
        raise ValueError("Invalid updatemethod specified, please use either put or patch.")
    results = client.set_policy(policy_id, update_method, policy_json)
    if results.get("success") is True:
        human_readable = "Update applied successfully to policy {}".format(args.get("policiyid"))
    results['id'] = args.get('policiyid')
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='GreatHorn.Policy',
        outputs_key_field='id',
        outputs=results
    )


def gh_get_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    policy_ids = argToList(args.get('policyid'))
    results = []
    if policy_ids:
        for policy_id in policy_ids:
            result = client.get_policy(policy_id)
            results.append(result.get("policy"))
    else:
        results = client.get_policy().get("policies", [])

    policies = []
    for r in results:
        if not isinstance(r, dict):  # Make mypy calm down about the policy dict
            continue
        actions = []
        for action in r.get("actions", []):
            actions.append(action.get("type"))
        policy = {
            "ID": r.get("id", ""),
            "Name": r.get("name", ""),
            "Enabled": r.get("enabled", ""),
            "Description": r.get("description", ""),
            "Actions": ",".join(actions)
        }
        policies.append(policy)
    policies_md = tableToMarkdown("Policy", policies, ["ID", "Name", "Enabled", "Description", "Actions"])

    return CommandResults(
        readable_output=policies_md,
        outputs_prefix='GreatHorn.Policy',
        outputs_key_field='id',
        outputs=results
    )


def gh_get_message_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ghid = argToList(args.get('id'))
    includeheaders = args.get('includeheaders', "false").lower() == "true"
    showalllinks = args.get('showalllinks', "false").lower() == "true"
    result = client.search_events({"filters": [{"eventId": ghid}]})

    if len(result.get("results", [])) > 0:
        message = result.get("results", [None])[0]

        envelope = {
            "ID": message.get("eventId"),
            "Received": message.get("timestamp"),
            "Mailbox": message.get("origin"),
            "Recipients": message.get("targets"),
            "Subject": message.get("subject"),
            "Display Name": message.get("displayName"),
            "From Address": message.get("source"),
            "From Domain": message.get("source").split("@")[-1],
            "Reply-To": message.get("replyTo"),
            "Return-Path": message.get("sourcePath"),
            "IP Address": message.get("ip"),
        }

        envelope_md = tableToMarkdown("Message Details", envelope, envelope.keys())

        authentication = {
            "SPF": message.get("spf"),
            "DKIM": message.get("dkim"),
            "DMARC": message.get("dmarc"),
            "Authentication Results": message.get("authenticationResults")
        }

        authentication_md = tableToMarkdown("Message Authentication", authentication, authentication.keys())

        scores = {
            "OWL": message.get("owlScore"),
            "Sender Anomaly": message.get("anomalyScore"),
            "Authenication Risk": message.get("authScore"),
            "Name Spoofing": message.get("homographScore")
        }

        scores_md = tableToMarkdown("Risk Analysis Factors", scores, scores.keys())

        links = []
        for link in message.get("links"):
            link_dict = {
                "Text": link.get("text"),
                "Url": link.get("url"),
                "Tags": ", ".join(link.get("tags", []))
            }
            if showalllinks:
                links.append(link_dict)
            else:
                if "suspicious" in link_dict['Tags'] or "malicious" in link_dict['Tags']:
                    links.append(link_dict)
            # break
        if showalllinks:
            links_md = tableToMarkdown("Links", links, ["Text", "Url", "Tags"])
        else:
            links_md = tableToMarkdown("Suspicious/Malicious Links", links, ["Text", "Url", "Tags"])

        files = []

        for file in message.get("files"):
            f = {
                "Name": file.get("fileName"),
                "Type": file.get("fileType"),
                "SHA256": file.get("fileHash")
            }
            files.append(f)

        files_md = tableToMarkdown("Files", files, ["Name", "Type", "SHA256"])

        policies = []

        if message.get("flag") is not None:
            for policy_id in message.get("flag"):
                policy = client.get_policy(policy_id).get("policy", {})
                actions = []
                for action in policy.get("actions"):
                    actions.append(action.get("type"))
                p = {
                    "ID": policy.get("id"),
                    "Name": policy.get("name"),
                    "Actions": ",".join(actions)
                }
                policies.append(p)

        policies_md = tableToMarkdown("Policies", policies, ["ID", "Name", "Actions"])

        headers = []
        msgheaders = message.get("headers")
        for header in message.get("headers").keys():
            h = {
                "Name": header,
                "Value": msgheaders[header]
            }
            headers.append(h)

        if includeheaders:
            headers_md = tableToMarkdown("Headers", headers, ["Name", "Value"])
        else:
            headers_md = ""

        message_md = envelope_md + authentication_md + scores_md + links_md + files_md + policies_md + headers_md

        return CommandResults(
            readable_output=message_md,
            outputs_prefix='GreatHorn.Message',
            outputs_key_field='eventId',
            outputs=result.get("results", [None])[0]
        )
    else:
        return CommandResults(
            readable_output="GreatHorn event not found",
            outputs={}
        )


def gh_get_phish_reports_command(client: Client):
    filter = [
        {
            "workflow": "reported phish"
        }
    ]
    results = client.search_events({"filters": filter, "limit": 100})
    incidents = []
    for event in results.get("results", []):
        incident = {}
        incident['name'] = event.get("subject")
        incident['occurred'] = event.get("timestamp")
        incident['rawJSON'] = json.dumps(event)
        client.remediate_message("review", {"eventId": event.get("eventId", 0)})
        incidents.append(incident)
    return incidents


def gh_get_quarantine_release_command(client: Client):
    filter = [
        {
            "quarReleaseRequested": "True",
            "workflow": "unreviewed"
        }
    ]
    results = client.search_events({"filters": filter, "limit": 100})
    incidents = []
    for event in results.get("results", []):
        incident = {}
        incident['name'] = event.get("subject")
        incident['occurred'] = event.get("timestamp")
        incident['rawJSON'] = json.dumps(event)
        client.remediate_message("review", {"eventId": event.get("eventId", 0)})
        incidents.append(incident)
    return incidents


''' MAIN FUNCTION '''


def main():
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')
    fetch_type = demisto.params().get('fetch_type')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], demisto.params()['api_version'])

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'gh-get-message':
            return_results(gh_get_message_command(client, demisto.args()))

        elif demisto.command() == 'gh-get-policy':
            return_results(gh_get_policy_command(client, demisto.args()))

        elif demisto.command() == 'gh-set-policy':
            return_results(gh_set_policy_command(client, demisto.args()))

        elif demisto.command() == 'gh-remediate-message':
            return_results(gh_remediate_message_command(client, demisto.args()))

        elif demisto.command() == 'gh-revert-remediate-message':
            return_results(gh_revert_remediate_message_command(client, demisto.args()))

        elif demisto.command() == 'gh-search-message':
            return_results(gh_search_message_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            if fetch_type is not None:
                last_run = demisto.getLastRun()
                demisto.info("GOT LAST RUN: {}".format(last_run))
                if not last_run.get("counter"):
                    counter = 0
                else:
                    counter = int(last_run.get("counter"))
                if counter % 3 == 0:
                    if fetch_type == "phishing":
                        incidents = gh_get_phish_reports_command(client)
                    elif fetch_type == "quarantine":
                        incidents = gh_get_quarantine_release_command(client)
                    else:
                        incidents_phish = gh_get_phish_reports_command(client)
                        incidents_quarantine = gh_get_quarantine_release_command(client)
                        incidents = incidents_phish
                        incidents.extend(incidents_quarantine)
                    demisto.incidents(incidents)
                counter += 1
                demisto.setLastRun({'max_phish_id': str(counter)})
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
