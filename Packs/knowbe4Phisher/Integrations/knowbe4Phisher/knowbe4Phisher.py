import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
import json
import urllib3
import dateparser
import traceback
import pytz

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

ALL_EVENTS_PAYLOAD = """query {{
  phisherMessages(all: false, page: 1, per: {}, query: ) {{
    nodes {{
      actionStatus
      attachments(status: UNKNOWN) {{
        actualContentType
        filename
        md5
        reportedContentType
        s3Key
        sha1
        sha256
        size
        ssdeep
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      category
      comments {{
        body
        createdAt
      }}
      events {{
        causer
        createdAt
        eventType
        events {{
          ...on PhisherEventEmails {{
            emails {{
              actionEmailId
              email
              status
              to
            }}
          }}
          ...on PhisherEventFieldChanges {{
            changes {{
              from
              name
              to
            }}
          }}
          ...on PhisherEventPhishFlipTemplateStatus {{
            kmsatTemplate
          }}
          ...on PhisherEventPhishML {{
            clean
            spam
            threat
          }}
          ...on PhisherEventPhishRipCompleted {{
            end
            quarantine
            read
            results
            start
            users
          }}
          ...on PhisherEventPhishRipStarted {{
            end
            quarantine
            start
          }}
          ...on PhisherEventReplayComplete {{
            complete
          }}
          ...on PhisherEventReplayTriggered {{
            runActions
          }}
          ...on PhisherEventSyslog {{
            name
          }}
          ...on PhisherEventTag {{
            added
            removed
          }}
          ...on PhisherEventVirusTotalResult {{
            identifier
            permalink
            positives
            scanDate
            scanned
            type
          }}
          ...on PhisherEventVirusTotalRun {{
            identifierNonNull: identifier
            type
          }}
          ...on PhisherEventWebhook {{
            name
          }}
        }}
        id
        triggerer
      }}
      from
      id
      links(status: UNKNOWN) {{
        dispositions
        firstSeen
        id
        lastSeen
        scheme
        target
        url
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      phishmlReport {{
        confidenceClean
        confidenceSpam
        confidenceThreat
      }}
      pipelineStatus
      rawUrl
      reportedBy
      rules {{
        createdAt
        description
        id
        matchedCount
        name
        tags
      }}
      severity
      subject
      tags {{
        name
        type
      }}
    }}
    pagination {{
      page
      pages
      per
      totalCount
    }}
  }}
}}"""

CREATE_COMMENT_PAYLOAD = """mutation {{
  phisherCommentCreate(comment: \\"{}\\", id: \\"{}\\") {{
    errors {{
      field
      placeholders
      reason
    }}
    node {{
      body
      createdAt
    }}
  }}
}}"""

UPDATE_STATUS_PAYLOAD = """mutation {{
  phisherMessageUpdate(id: \\"{}\\", payload: {}) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}  
}}
"""

CREATE_TAGS_PAYLOAD = """mutation {{
  phisherTagsCreate(id: \\"{}\\", tags: [{}]) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}
}}
"""

DELETE_TAGS_PAYLOAD = """mutation {{
   phisherTagsDelete(id: \\"{}\\", tags: [{}]) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}
}}
"""

NUMBER_OF_MESSAGES = """query {
  phisherMessages(all: false, page: 1, per: 25, query: ) {
    pagination {
      page
      pages
      per
      totalCount
    }
  }
}
"""

FETCH_WITHOUT_EVENTS = """query {{
  phisherMessages(all: false, page: 1, per: {}, query: ) {{
    nodes {{
      actionStatus
      attachments(status: UNKNOWN) {{
        actualContentType
        filename
        md5
        reportedContentType
        s3Key
        sha1
        sha256
        size
        ssdeep
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      category
      comments {{
        body
        createdAt
      }}
      events {{
        causer
        createdAt
        eventType
        id
        triggerer
      }}
      from
      id
      links(status: UNKNOWN) {{
        dispositions
        firstSeen
        id
        lastSeen
        scheme
        target
        url
        virustotal {{
          permalink
          positives
          scanned
          sha256
        }}
      }}
      phishmlReport {{
        confidenceClean
        confidenceSpam
        confidenceThreat
      }}
      pipelineStatus
      rawUrl
      reportedBy
      rules {{
        createdAt
        description
        id
        matchedCount
        name
        tags
      }}
      severity
      subject
      tags {{
        name
        type
      }}
    }}
    pagination {{
      page
      pages
      per
      totalCount
    }}
  }}
}}"""

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def phisher_message_list_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_get_number_of_messages_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_message_list_all_events_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_create_comment_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_update_message_status_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_create_tags_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )

    def phisher_delete_tags_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )


''' HELPER FUNCTIONS '''


def create_request(st: str):
    """ Function that creates a valid request to use in http_request.

    argument: a multiline string with a request in a human readable format

    return: a final string that is formatted to suit the http_request function
    """
    format_desc = st.splitlines()
    final = ""
    for i in format_desc:
        final = final + i + '\\n'
    final = final[:-2]
    return final


def create_gql_query(payload: str, query: str):
    """
    for gql query - the query argument inside the request should be with double quotes.
    this function is inserting the query parameter to the request body and adds the needed parameters,
    for gql query - wrapping the query in a dictionary representation

    arguments: payload, the body part of a request. query, the query parameter from phisherMessages arguments

    output: a string with dict representation of gql query.
    """
    st = "query:"
    j = len(st)
    i = payload.find(st)
    temp = payload[:i + j] + query + payload[i + j:]
    return "{\"query\": \"" + temp + "\",\"variables\": {}}"


def get_last_fetch_time(last_run: dict, first_fetch_time: str):
    """
    this helper function will get the demisto.getLastRun() and first_fetch_time parameter
    and will return:
    last_time - timestamp of last message fetched
    query - the query parameter with the timestamp to match the Phisher filter
    """
    # Get the last fetch time, if exists
    utc = pytz.UTC
    last_fetch = last_run.get('last_fetch')
    # Handle first time fetch
    if last_fetch is None:
        last_fetch = dateparser.parse(first_fetch_time)
        time_param = last_fetch.strftime(DATE_FORMAT)
        query = "\\\" reported_at:[" + time_param + " TO *]\\\""
    else:
        last_fetch = dateparser.parse(last_fetch)
        time_param = last_fetch.strftime(DATE_FORMAT)
        query = "\\\" reported_at:[" + time_param + " TO *]\\\""
    last_time = last_fetch.replace(tzinfo=utc)
    return last_time, query


def calculate_number_of_events(client: Client, query: str):
    """
    function gets the formatted query with the relevant timestamp
    and returns number of events to fetch
    """
    # get number of new events
    payload = create_gql_query(NUMBER_OF_MESSAGES, query)
    req = create_request(payload)
    limit_req = client.phisher_get_number_of_messages_request(req)
    return str(limit_req.get('data', {}).get('phisherMessages', {}).get('pagination', {}).get('totalCount'))


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity, authentication and parameters for fetch incidents

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    param Client: client to use

    return: 'ok' if test passed, specific error if with a suggestion of how to fix.
    """
    first_fetch_time = params.get('first_fetch')
    try:
        fetch_limit = int(params.get('max_fetch'))
    except ValueError:
        return 'Fetch Limit should be set as an integer'

    try:
        _, incidents = fetch_incidents(
            client=client,
            last_run=demisto.getLastRun(),
            first_fetch_time=first_fetch_time,
            max_fetch=fetch_limit)

        if incidents:
            return 'ok'
    except Exception as e:
        if 'Unauthorized' in str(e):
            return 'Authorization Error: make sure API Key was set correctly'
        elif 'NoneType' in str(e):
            return 'Check the format of First Fetch Time'
        elif 'Failed to parse json' in str(e):
            return 'Please check the specified URL'
        else:
            return 'Unknown error, please check your configuration'


def phisher_message_list_command(client: Client, args: dict) -> CommandResults:
    """
    this function implements the message-list-command.
    arguments of command:
    limit - maximum number of messages to retrieve. default - 200
    query - a lucene query for entered by a user to filter results. default - empty
    message_id - id of specific message to retrieve, once it's entered the query parameter is ignored.
    all_events - if set to false message will be retrieved without associated events. on true all events will be
    retrieved to the XSOAR context. default is false.

    arguments of function:
    client and arguments

    return: all relevant messages returned in the commandResults structure to war room and context of XSOAR

    """
    # get parameters
    limit = args.get('limit')
    query = args.get('query')
    message_id = args.get('id')
    all_events = args.get('include_events')
    # handle query
    if not query:
        query = "\\\"\\\""
    else:
        query = "\\\"" + args.get('query') + "\\\""
    # handle in case ID is given
    if message_id:
        query = "\\\"id:" + message_id + "\\\""
    # create request body
    query = query.lower()
    payload_init = ALL_EVENTS_PAYLOAD.format(limit)
    payload = create_gql_query(payload_init, query)
    req = create_request(payload)
    # call the API
    result = client.phisher_message_list_all_events_request(req)
    messages = result.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    readable = []
    # creata data for XSOAR
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


def phisher_create_comment_command(client: Client, args: dict) -> str:
    """
    this function implements the create-comment command
    command used in XSOAR to create a comment for a specific gived ID of a message.
    arguments of command:
    id - message id, required.
    comment - comment to be added, required.

    arguments of function:
    client - Base client
    args - dict with command arguments

    output - indication to war room if the operation was successful or not

    """
    id = args.get('id')
    comment = args.get('comment')

    # create the request body
    payload = CREATE_COMMENT_PAYLOAD.format(comment, id)
    final = "{\"query\": \"" + payload + "\",\"variables\": {}}"
    final_req = create_request(final)
    # call request
    result = client.phisher_create_comment_request(final_req)
    res = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not res:
        return "The comment was added successfully"
    else:
        return "The comment wasn't added - Verify ID is correct"


def phisher_update_message_status_command(client: Client, args: dict) -> str:
    """
    this function implements the update-message-status command
    this function will receive the veluas to be updated and ID of a specific message and will update
    the status of this message

    command arguments:
    id - message id, required.
    category - category of message, possible values: Unknown, Clean, Spam, Threat
    severity - severity of message, possible values: Unknown, Low, Medium, High, Critical
    status - status of message, possible values: Received, In_Review, Resolved

    function arguments:
    client and command arguments.

    function returns indication if the update was successful.
    at least one of the arguments should be given in order for the function to work.
    """
    # get arguments
    id = args.get('id')
    category = args.get('category')
    status = args.get('status')
    severity = args.get('severity')
    # create the attributes dict for arguments to update
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
    # create the request body
    payload = UPDATE_STATUS_PAYLOAD.format(id, attr_str)
    final = "{\"query\":\"" + payload + "\",\"variables\": {}}"
    final_req = create_request(final)
    # call request
    result = client.phisher_update_message_status_request(final_req)
    res = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not res:
        return "The message was updated successfully"
    else:
        return "The message wasn't updated - check if ID is correct and the parameters are without syntax errors"


def phisher_create_tags_command(client: Client, args: dict) -> str:
    """
    this function implements the create-tags-command
    adding the specified tags to the given message ID

    command arguments:
    id - message ID, required.
    tags - message tags, required. should be given in double quotes seperated by comma

    function arguments:
    client and arguments

    function returns and indication if the tag was added successfully or not.
    """
    # get arguments
    id = args.get('id')
    tags = args.get('tags')
    # create the format for tags that expected by Phisher
    arg_tags = argToList(tags)
    parsed_tags = ""
    for tag in arg_tags:
        if not parsed_tags:
            parsed_tags = "\\\"" + tag + "\\\""
        else:
            parsed_tags = parsed_tags + ", \\\"" + tag + "\\\""
    # create the request body
    payload = CREATE_TAGS_PAYLOAD.format(id, parsed_tags)
    final = "{\"query\":\"" + payload + "\",\"variables\": {}}"
    final_req = create_request(final)
    # call request
    result = client.phisher_create_tags_request(final_req)
    res = result.get('data', {}).get('phisherTagsCreate', {}).get('errors', "")

    if not res:
        return "The tags were updated successfully"
    else:
        return "The tags weren't added - check the ID"


def phisher_delete_tags_command(client: Client, args: dict) -> str:
    """
    this function implements the delete-tags-command
    deleting the specified tags to the given message ID

    command arguments:
    id - message ID, required.
    tags - message tags, required. should be given in double quotes seperated by comma

    function arguments:
    client and arguments

    function returns and indication if the tag was added successfully or not.
    the indication is only checking if the provided ID exist in the system.
    the API gives same response if user tries to delete an existing or not existing tags
    so there is no way to differentiate between deleting existing tag or not existing tag.
    """
    # get arguments
    id = args.get('id')
    tags = args.get('tags')
    # create the format for tags that expected by Phisher
    arg_tags = argToList(tags)
    parsed_tags = ""
    for tag in arg_tags:
        if not parsed_tags:
            parsed_tags = "\\\"" + tag + "\\\""
        else:
            parsed_tags = parsed_tags + ", \\\"" + tag + "\\\""
    # create the request body
    payload = DELETE_TAGS_PAYLOAD.format(id, parsed_tags)
    final = "{\"query\":\"" + payload + "\",\"variables\": {}}"
    final_req = create_request(final)
    result = client.phisher_delete_tags_request(final_req)
    res = result.get('data', {}).get('phisherTagsCreate', {}).get('errors', "")

    if not res:
        return "The tags were deleted successfully"
    else:
        return "The tags weren't deleted - check the ID"


def fetch_incidents(client: Client, last_run: dict, first_fetch_time: str, max_fetch: int):
    """
    fetch_incidents is being called from the fetch_incidents_command function.
    it checks the last message fetch, checking number of new events, and getting all messages
    going through all messages to and saving them to incidents list.

    returning incidents list and the time the las message was retrieved - so that next run will
    automatically continue from the same place.
    """
    last_time, query = get_last_fetch_time(last_run, first_fetch_time)
    limit = calculate_number_of_events(client, query)
    incidents = []
    # create request
    payload_init = FETCH_WITHOUT_EVENTS.format(limit)
    payload = create_gql_query(payload_init, query)
    req = create_request(payload)
    # get all messages
    messages = client.phisher_message_list_request(req)
    items = messages.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    # check if they need to be fetched
    message_index = 0
    for item in reversed(items):
        events = item.get('events', {})
        for event in events:
            if (event['eventType']) == 'CREATED':
                creation_time = (event['createdAt'])
                break
        incident_created_time = dateparser.parse(creation_time)
        item["created at"] = incident_created_time.strftime(DATE_FORMAT)
        item.pop("events")
        incident = {
            'name': item['subject'],
            'occurred': incident_created_time.strftime(DATE_FORMAT),
            'rawJSON': json.dumps(item)
        }

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > last_time:
            last_time = incident_created_time
            incidents.append(incident)
        message_index += 1
        if message_index == max_fetch:
            break

    next_run = {'last_fetch': last_time.strftime('%Y-%m-%dT%H:%M:%SZ')}
    return next_run, incidents


def fetch_incidents_command(client: Client, params: dict):
    """
    calling the fetch incidents and writing all incidents to demisto.incidents.
    """
    first_fetch_time = params.get('first_fetch')
    fetch_limit = int(params.get('max_fetch'))
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=demisto.getLastRun(),
        first_fetch_time=first_fetch_time,
        max_fetch=fetch_limit)
    demisto.setLastRun(next_run)
    demisto.incidents(incidents)


''' MAIN FUNCTION '''


def main(params: dict, args: dict, command: str) -> None:
    # get the service API url
    url = params.get('url')
    key = params.get('apikey', {}).get('password')
    insecure = not params.get('insecure', False)

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
            return_results(test_module(client, params))
        elif command == 'fetch-incidents':
            fetch_incidents_command(client, params)
        elif command == 'phisher-message-list':
            return_results(phisher_message_list_command(client, args))
        elif command == 'phisher-create-comment':
            return_results(phisher_create_comment_command(client, args))
        elif command == 'phisher-update-message-status':
            return_results(phisher_update_message_status_command(client, args))
        elif command == 'phisher-create-tags':
            return_results(phisher_create_tags_command(client, args))
        elif command == 'phisher-delete-tags':
            return_results(phisher_delete_tags_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params(), demisto.args(), demisto.command())
