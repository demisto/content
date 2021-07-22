import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
import json
import urllib3
import dateparser
import traceback
import pytz
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def phisher_message_list_request(self, limit: str, query: str):
        payload = "{\"query\":\"query {\\n  phisherMessages(all: false, page: 1, per: " + limit + ", query: " + query + ") {\\n    nodes {\\n      actionStatus\\n      attachments(status: UNKNOWN) {\\n        actualContentType\\n        filename\\n        md5\\n        reportedContentType\\n        s3Key\\n        sha1\\n        sha256\\n        size\\n        ssdeep\\n        virustotal {\\n          permalink\\n          positives\\n          scanned\\n          sha256\\n        }\\n      }\\n      category\\n      comments {\\n        body\\n        createdAt\\n      }\\n      events {\\n        causer\\n        createdAt\\n        eventType\\n        id\\n        triggerer\\n      }\\n      from\\n      id\\n      links(status: UNKNOWN) {\\n        dispositions\\n        firstSeen\\n        id\\n        lastSeen\\n        scheme\\n        target\\n        url\\n        virustotal {\\n          permalink\\n          positives\\n          scanned\\n          sha256\\n        }\\n      }\\n      phishmlReport {\\n        confidenceClean\\n        confidenceSpam\\n        confidenceThreat\\n      }\\n      pipelineStatus\\n      rawUrl\\n      reportedBy\\n      rules {\\n        createdAt\\n        description\\n        id\\n        matchedCount\\n        name\\n        tags\\n      }\\n      severity\\n      subject\\n      tags {\\n        name\\n        type\\n      }\\n    }\\n    pagination {\\n      page\\n      pages\\n      per\\n      totalCount\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_get_number_of_messages_requst(self, query: str):
        payload = "{\"query\":\"query {\\n  phisherMessages(all: false, page: 1, per: 25, query:" + query + \
                  ") {\\n    pagination {\\n      page\\n      pages\\n      per\\n      totalCount\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_message_list_all_events_requst(self, limit: str, query: str):
        payload = "{\"query\":\"query {\\n  phisherMessages(all: false, page: 1, per: " + limit + ", query: " + query + ") {\\n    nodes {\\n      actionStatus\\n      attachments(status: UNKNOWN) {\\n        actualContentType\\n        filename\\n        md5\\n        reportedContentType\\n        s3Key\\n        sha1\\n        sha256\\n        size\\n        ssdeep\\n        virustotal {\\n          permalink\\n          positives\\n          scanned\\n          sha256\\n        }\\n      }\\n      category\\n      comments {\\n        body\\n        createdAt\\n      }\\n      events {\\n        causer\\n        createdAt\\n        eventType\\n        events {\\n          ...on PhisherEventEmails {\\n            emails {\\n              actionEmailId\\n              email\\n              status\\n              to\\n            }\\n          }\\n          ...on PhisherEventFieldChanges {\\n            changes {\\n              from\\n              name\\n              to\\n            }\\n          }\\n          ...on PhisherEventPhishFlipTemplateStatus {\\n            kmsatTemplate\\n          }\\n          ...on PhisherEventPhishML {\\n            clean\\n            spam\\n            threat\\n          }\\n          ...on PhisherEventPhishRipCompleted {\\n            end\\n            quarantine\\n            read\\n            results\\n            start\\n            users\\n          }\\n          ...on PhisherEventPhishRipStarted {\\n            end\\n            quarantine\\n            start\\n          }\\n          ...on PhisherEventReplayComplete {\\n            complete\\n          }\\n          ...on PhisherEventReplayTriggered {\\n            runActions\\n          }\\n          ...on PhisherEventSyslog {\\n            name\\n          }\\n          ...on PhisherEventTag {\\n            added\\n            removed\\n          }\\n          ...on PhisherEventVirusTotalResult {\\n            identifier\\n            permalink\\n            positives\\n            scanDate\\n            scanned\\n            type\\n          }\\n          ...on PhisherEventVirusTotalRun {\\n            identifierNonNull: identifier\\n            type\\n          }\\n          ...on PhisherEventWebhook {\\n            name\\n          }\\n        }\\n        id\\n        triggerer\\n      }\\n      from\\n      id\\n      links(status: UNKNOWN) {\\n        dispositions\\n        firstSeen\\n        id\\n        lastSeen\\n        scheme\\n        target\\n        url\\n        virustotal {\\n          permalink\\n          positives\\n          scanned\\n          sha256\\n        }\\n      }\\n      phishmlReport {\\n        confidenceClean\\n        confidenceSpam\\n        confidenceThreat\\n      }\\n      pipelineStatus\\n      rawUrl\\n      reportedBy\\n      rules {\\n        createdAt\\n        description\\n        id\\n        matchedCount\\n        name\\n        tags\\n      }\\n      severity\\n      subject\\n      tags {\\n        name\\n        type\\n      }\\n    }\\n    pagination {\\n      page\\n      pages\\n      per\\n      totalCount\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_create_comment_request(self, id: str, comment: str):
        payload = "{\"query\":\"mutation {\\n  phisherCommentCreate(comment: \\\"" + comment + "\\\", id: \\\"" + id + \
                  "\\\") {\\n    errors {\\n      field\\n      placeholders\\n      reason\\n    }\\n    node {\\n      body\\n      createdAt\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_update_message_status_request(self, id: str, attributes: str):
        payload = "{\"query\":\"mutation {\\n  phisherMessageUpdate(id: \\\"" + id + "\\\", payload: " + attributes + \
                  ") {\\n    errors {\\n      field\\n      placeholders\\n      reason\\n    }\\n  }  \\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_create_tags_request(self, id: str, tags: str):
        payload = "{\"query\":\"mutation {\\n  phisherTagsCreate(id: \\\"" + id + "\\\", tags: [" + tags + \
                  "]) {\\n    errors {\\n      field\\n      placeholders\\n      reason\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_delete_tags_request(self, id: str, tags: str):
        payload = "{\"query\":\"mutation {\\n  phisherTagsDelete(id: \\\"" + id + "\\\", tags: [" + tags + \
                  "]) {\\n    errors {\\n      field\\n      placeholders\\n      reason\\n    }\\n  }\\n}\\n\",\"variables\":{}}"
        return self._http_request(
            method='POST',
            data=payload
        )


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    return_all = "false"
    page = "1"
    per_page = "25"
    query = "\\\"\\\""
    message: str = ''
    try:
        client.phisher_get_all_messages_request(return_all, page, per_page, query)
        message = 'ok'
    except DemistoException as e:
        if 'Unauthorized' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = 'Please check the specified URL'
    return message


def phisher_message_list_command(client: Client) -> CommandResults:
    args = demisto.args()
    limit = args.get('limit')
    # limit = '200'
    query = args.get('query')
    message_id = args.get('id')
    all_events = args.get('include_events')
    # all_events = False
    if not query:
        query = "\\\"\\\""
    else:
        query = "\\\"" + args.get('query') + "\\\""

    if message_id:
        query = "\\\"id:" + message_id + "\\\""

    query = query.lower()
    result = client.phisher_message_list_all_events_requst(limit, query)
    messages = result.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    readable = []
    for item in messages:
        # find creation time and create a key with this value
        events = item.get('events', {})
        for event in events:
            if (event['eventType']) == 'CREATED':
                creation_time = (event['createdAt'])
                break
        incident_created_time = dateparser.parse(creation_time)
        if all_events == "False":
            item.pop("events")
        item["created at"] = incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ')

        # prepare printout to war room
        readable.append({"ID": item.get('id', ""), "Status": item.get('actionStatus', ""), "Category": item.get(
            'category', ""), "From": item.get('from', ""), "Severity": item.get('severity', "")})

    markdown = '### The requested information:\n'
    markdown += tableToMarkdown('Messages', readable, headers=['ID', 'Status', 'Category', 'From', 'Severity'])
    res = CommandResults(
        outputs_prefix='Phisher.Message',
        outputs_key_field='id',
        readable_output=markdown,
        outputs=messages
    )
    return res


def phisher_create_comment_command(client: Client) -> str:
    id = demisto.args().get('id')
    comment = demisto.args().get('comment')
    result = client.phisher_create_comment_request(id, comment)
    res = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not res:
        return "The comment was added successfully"
    else:
        return "The comment wasn't added - Verify ID is correct"


def phisher_update_message_status_command(client: Client) -> str:
    id = demisto.args().get('id')
    category = demisto.args().get('category')
    status = demisto.args().get('status')
    severity = demisto.args().get('severity')
    attributes = {}
    if category:
        attributes["category"] = category
    if status:
        attributes["status"] = status
    if severity:
        attributes["severity"] = severity
    if not (category or status or severity):
        return "None of the parameters was set - Please specify at least one of the parameters"
    attr_str = json.dumps(attributes)
    attr_str = attr_str.replace('\"', '')
    attr_str = attr_str.replace(' ', '')
    result = client.phisher_update_message_status_request(id, attr_str)
    res = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not res:
        return "The message was updated successfully"
    else:
        return "The message wasn't updated - check if ID is correct and the parameters are without syntax errors"


def phisher_create_tags_command(client: Client) -> str:
    id = demisto.args().get('id')
    tags = demisto.args().get('tags')
    # create the format for tags that expected by Phisher
    arg_tags = argToList(tags)
    parsed_tags = ""
    for tag in arg_tags:
        if not parsed_tags:
            parsed_tags = "\\\"" + tag + "\\\""
        else:
            parsed_tags = parsed_tags + ", \\\"" + tag + "\\\""

    result = client.phisher_create_tags_request(id, parsed_tags)
    res = result.get('data', {}).get('phisherTagsCreate', {}).get('errors', "")

    if not res:
        return "The tags were updated successfully"
    else:
        return "The tags weren't added - check the ID"


def phisher_delete_tags_command(client: Client) -> str:
    id = demisto.args().get('id')
    tags = demisto.args().get('tags')
    # create the format for tags that expected by Phisher
    arg_tags = argToList(tags)
    parsed_tags = ""
    for tag in arg_tags:
        if not parsed_tags:
            parsed_tags = "\\\"" + tag + "\\\""
        else:
            parsed_tags = parsed_tags + ", \\\"" + tag + "\\\""
    result = client.phisher_delete_tags_request(id, parsed_tags)
    res = result.get('data', {}).get('phisherTagsCreate', {}).get('errors', "")

    if not res:
        return "The tags were deleted successfully"
    else:
        return "The tags weren't deleted - check the ID"


def fetch_incidents(client: Client, last_run, first_fetch_time):
    # Get the last fetch time, if exists
    utc = pytz.UTC
    last_fetch = last_run.get('last_fetch')
    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
        time_param = last_fetch.strftime('%Y-%m-%dT%H:%M:%SZ')
        query = "\\\" reported_at:[" + time_param + " TO *]\\\""
    else:
        last_fetch = dateparser.parse(last_fetch)
        time_param = last_fetch.strftime('%Y-%m-%dT%H:%M:%SZ')
        query = "\\\" reported_at:[" + time_param + " TO *]\\\""

    last_time = last_fetch.replace(tzinfo=utc)
    incidents = []
    # get number of new events
    limit_req = client.phisher_get_number_of_messages_requst(query)
    limit = str(limit_req.get('data', {}).get('phisherMessages', {}).get('pagination', {}).get('totalCount'))

    messages = client.phisher_message_list_request(limit, query)
    items = messages.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    for item in reversed(items):
        events = item.get('events', {})
        for event in events:
            if (event['eventType']) == 'CREATED':
                creation_time = (event['createdAt'])
                break
        incident_created_time = dateparser.parse(creation_time)
        item["created at"] = incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        item.pop("events")
        incident = {
            'name': item['subject'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > last_time:
            last_time = incident_created_time
            incidents.append(incident)

    next_run = {'last_fetch': last_time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    # get the service API url
    url = demisto.params().get('url', 'https://eu.knowbe4.com/graphql')
    key = demisto.params().get('apikey', {}).get('password')
    first_fetch_time = demisto.params().get('first_fetch')
    insecure = not demisto.params().get('insecure', False)
    headers = {
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json'
    }

    demisto.debug(f'Command being called is {command}')
    try:

        client = Client(
            base_url=url,
            verify=insecure,
            headers=headers,
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'phisher-message-list':
            return_results(phisher_message_list_command(client))
        elif command == 'phisher-create-comment':
            return_results(phisher_create_comment_command(client))
        elif command == 'phisher-update-message-status':
            return_results(phisher_update_message_status_command(client))
        elif command == 'phisher-create-tags':
            return_results(phisher_create_tags_command(client))
        elif command == 'phisher-delete-tags':
            return_results(phisher_delete_tags_command(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
