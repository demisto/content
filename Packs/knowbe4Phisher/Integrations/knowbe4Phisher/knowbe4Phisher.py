from CommonServerPython import *
# noqa: F401
# noqa: F401
import json
import urllib3
import traceback


# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

ALL_EVENTS_PAYLOAD = """query {{
  phisherMessages(all: false, page: 1, per: {}, query: {}) {{
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
  phisherCommentCreate(comment: \"{}\", id: \"{}\") {{
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
  phisherMessageUpdate(id: \"{}\", payload: {}) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}
}}
"""

CREATE_TAGS_PAYLOAD = """mutation {{
  phisherTagsCreate(id: \"{}\", tags: [{}]) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}
}}
"""

DELETE_TAGS_PAYLOAD = """mutation {{
   phisherTagsDelete(id: \"{}\", tags: [{}]) {{
    errors {{
      field
      placeholders
      reason
    }}
  }}
}}
"""

NUMBER_OF_MESSAGES = """query {{
  phisherMessages(all: false, page: 1, per: 25, query: {}) {{
    pagination {{
      page
      pages
      per
      totalCount
    }}
  }}
}}
"""

FETCH_WITHOUT_EVENTS = """query {{
  phisherMessages(all: false, page: 1, per: {}, query: {}) {{
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

    def __init__(self, base_url, verify, proxy, first_fetch_time, headers=None, max_fetch=None):
        self.first_fetch_time = first_fetch_time
        self.max_fetch = max_fetch

        if not headers:
            headers = {}

        headers["X-KB4-Integration"] = "Cortex XSOAR PhishER"
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    def phisher_gql_request(self, payload: str):
        return self._http_request(
            method='POST',
            data=payload
        )


''' HELPER FUNCTIONS '''


def create_gql_request(readable_request: str) -> str:
    """ Function that creates a valid request to use in http_request.

    args:
        st (String): A multiline string with a request in a human readable format

    Returns:
        A string that is formatted to suit the http_request function
    """
    format_desc = readable_request.splitlines()
    final = ""
    for line in format_desc:
        final += line + '\\n'
    return final[:-2]


def calculate_number_of_events(client: Client, query: str) -> str:
    """
    function that calculates number of events that fulfilling the query parameter

    args:
        client (Client): Phisher client
        query (String): query with the timestamp in a lucene query format

    returns:
        number of events to fetch
    """
    # get number of new events
    payload_init = NUMBER_OF_MESSAGES.format(query)
    payload = json.dumps({'query': payload_init, 'variables': {}})
    req = create_gql_request(payload)
    events_req = client.phisher_gql_request(req)
    return str(events_req.get('data', {}).get('phisherMessages', {}).get('pagination', {}).get('totalCount'))


def get_created_time(events: list) -> str:
    creation_time = ""
    for event in events:
        if (event['eventType']) == 'CREATED':
            creation_time = (event['createdAt'])
            break
    return creation_time


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity, authentication and parameters for fetch incidents

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    args:
        client (Client): Phisher client

    returns:
        'ok' if test passed, specific error if with a suggestion of how to fix.
    """
    first_fetch_time = client.first_fetch_time
    try:
        fetch_limit = client.max_fetch  # type: ignore
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
        else:
            return 'no data in the system, but connection looks ok'
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

    arguments:
        client (Client): Phisher client
        args (Dict): dictionary with all command arguments
            limit (String): limit of the number of messages to get with this command
            query (String): query parameter for the message list command
            message_id (String): message id by which to query
            all_events (Boolean): True - to include all events in the response, False - to return messages without events

    return:
        all relevant messages returned in the commandResults structure to war room and context of XSOAR

    """
    # get parameters
    limit = client.max_fetch
    query = args.get('query')
    message_id = args.get('id')
    all_events = args.get('include_events')
    # handle query
    if not query:
        q = '\"\"'
        query = f'{q}'
    else:
        query = f'\"{query}\"'
    # handle in case ID is given
    if message_id:
        query = f'\"id:{message_id}\"'
    # create request body
    query = query.lower()
    payload_init = ALL_EVENTS_PAYLOAD.format(limit, query)
    payload = json.dumps({'query': payload_init, 'variables': {}})
    req = create_gql_request(payload)
    # call the API
    result = client.phisher_gql_request(req)
    messages = result.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    readable = []
    # creata data for XSOAR
    for message in messages:
        # find creation time and create a key with this value
        events = message.get('events', {})
        creation_time = get_created_time(events)
        message["created at"] = arg_to_datetime(creation_time).isoformat()  # type: ignore
        if all_events == "False":
            message.pop("events")

        # prepare printout to war room
        readable.append(
            {"ID": message.get('id', ""), "Status": message.get('actionStatus', ""), "Category": message.get(
                'category', ""), "From": message.get('from', ""), "Severity": message.get('severity', ""),
             "Created At": message.get('created at', "")})

    markdown = tableToMarkdown('Messages', readable, headers=['ID', 'Status', 'Category', 'From', 'Severity', 'Created At'])
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
    command used in XSOAR to create a comment for a specific giveN ID of a message.

    Args:
        client (Client): Phisher client
        args (Dict): Dictionary with command arguments
            message_id (String): message id
            Comment (String): the comment to add to the message

    Returns:
        indication to war room if the operation was successful or not
    """
    message_id = args.get('id')
    comment = args.get('comment')

    # create the request body
    payload = CREATE_COMMENT_PAYLOAD.format(comment, message_id)
    final = json.dumps({'query': payload, 'variables': {}})
    final_str = create_gql_request(final)
    # call request
    result = client.phisher_gql_request(final_str)
    errors = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not errors:
        return "The comment was added successfully"
    else:
        return "The comment wasn't added - Verify ID is correct"


def phisher_update_message_command(client: Client, args: dict) -> str:
    """
    this function implements the update-message command
    this function will receive the values to be updated and ID of a specific message and will update
    the status of this message

    Args:
        client (Client): Phisher client
        args (Dict): Dictionary with command arguments consists the below arguments
            id: message id, required.
            category: category of message, possible values: Unknown, Clean, Spam, Threat
            severity: severity of message, possible values: Unknown, Low, Medium, High, Critical
            status: status of message, possible values: Received, In_Review, Resolved
            at least one of the arguments should be given in order for the function to work.

    Returns:
        returns indication if the update was successful.
    """
    # get arguments
    message_id = args.get('id')
    category = args.get('category')
    status = args.get('status')
    severity = args.get('severity')
    # create the attributes dict for arguments to update
    attributes = assign_params(category=category, status=status, severity=severity)
    if not attributes:
        return "No message argument was given. Specify at least one of the following: category, status, severity"
    attr_str = json.dumps(attributes)
    attr_str = attr_str.replace('\"', '')
    attr_str = attr_str.replace(' ', '')
    # create the request body
    payload = UPDATE_STATUS_PAYLOAD.format(message_id, attr_str)
    final = json.dumps({'query': payload, 'variables': {}})
    final_req = create_gql_request(final)
    # call request
    result = client.phisher_gql_request(final_req)
    errors = result.get('data', {}).get('phisherCommentCreate', {}).get('errors', "")

    if not errors:
        return "The message was updated successfully"
    else:
        return "The message wasn't updated - check if ID is correct and the parameters are without syntax errors"


def phisher_create_tags_command(client: Client, args: dict) -> str:
    """
    this function implements the create-tags-command
    adding the specified tags to the given message ID

    args:
        client (Client): Phisher client
        args (Dict): Dictionary with command arguments with the below arguments
            id: message ID, required.
            tags: message tags, required. should be given in double quotes separated by comma

    returns:
        returns an indication if the tag was added successfully or not.
    """
    # get arguments
    message_id = args.get('id')
    # create the format for tags that expected by Phisher
    tags = argToList(args.get('tags'))
    parsed_tags = ""
    for tag in tags:
        if not parsed_tags:
            parsed_tags = f'\"{tag}\"'
        else:
            parsed_tags = f'{parsed_tags}, \"{tag}\"'
    # create the request body
    payload = CREATE_TAGS_PAYLOAD.format(message_id, parsed_tags)
    final = json.dumps({'query': payload, 'variables': {}})
    final_req = create_gql_request(final)
    # call request
    result = client.phisher_gql_request(final_req)
    errors = result.get('data', {}).get('phisherTagsCreate', {}).get('errors', "")

    if not errors:
        return "The tags were updated successfully"
    else:
        return "The tags weren't added - check the ID"


def phisher_delete_tags_command(client: Client, args: dict) -> str:
    """
    This function implements the delete-tags-command deleting the specified tags to the given message ID.
    The indication is only checking if the provided ID exist in the system.
    The API gives same response if user tries to delete an existing or not existing tags so there is no way to differentiate
    between deleting existing tag or not existing tag.
    args:
        client (Client): Phisher client
        args (Dict): Dictionary with command arguments with the below arguments:
            id: message ID, required.
            tags: message tags, required. should be given in double quotes separated by comma

    returns:
        An indication if the tag was added successfully or not.
    """
    # get arguments
    message_id = args.get('id')
    # create the format for tags that expected by Phisher
    tags = argToList(args.get('tags'))
    parsed_tags = ""
    for tag in tags:
        if not parsed_tags:
            parsed_tags = f'\"{tag}\"'
        else:
            parsed_tags = f'{parsed_tags}, \"{tag}\"'
    # create the request body
    payload = DELETE_TAGS_PAYLOAD.format(message_id, parsed_tags)
    final = json.dumps({'query': payload, 'variables': {}})
    final_req = create_gql_request(final)
    result = client.phisher_gql_request(final_req)
    errors = result.get('data', {}).get('phisherTagsDelete', {}).get('errors', "")

    if not errors:
        return "The tags were deleted successfully"
    else:
        return "The tags weren't deleted - check the ID"


def fetch_incidents(client: Client, last_run: dict, first_fetch_time: str, max_fetch: int) -> tuple[str, list]:
    """
    fetch_incidents is being called from the fetch_incidents_command function.
    it checks the last message fetch, checking number of new events, and getting all messages
    that are newer than then the last message fetched or the first fetch time entered by user,
    afterwards the function is going through all messages to and saving them to incidents list.

    returning incidents list and the time the las message was retrieved - so that next run will
    automatically continue from the same place.

    args:
        client (Client): Phisher client
        last_run (Dict): dict containing the time of the last fetched message
        first_fetch_time (String): the first fetch parameter from integration instance for the first fetch
        max_fetch (Int): maximum number for each fetch

    returns:
        next_run: timestamp of the last message fetched so next fetch will know from where to start
        incidents: list of incidents to be written to XSOAR
    """
    last_time = last_run.get('last_fetch', first_fetch_time)
    query = f'\" reported_at:[{last_time} TO *]\"'
    limit = calculate_number_of_events(client, query)
    incidents = []
    # create request
    payload_init = FETCH_WITHOUT_EVENTS.format(limit, query)
    payload = json.dumps({'query': payload_init, 'variables': {}})
    req = create_gql_request(payload)
    # get all messages
    items = client.phisher_gql_request(req)
    messages = items.get('data', {}).get('phisherMessages', {}).get('nodes', [])
    # check if they need to be fetched
    message_index = 0
    for message in reversed(messages):
        events = message.get('events', {})
        creation_time = get_created_time(events)
        message["created at"] = arg_to_datetime(creation_time).isoformat()  # type: ignore
        message.pop("events")
        incident = {
            'name': message.get('subject'),
            'occurred': message.get('created at'),
            'rawJSON': json.dumps(message)
        }

        # Update last run and add incident if the incident is newer than last fetch
        last_time = message["created at"]
        incidents.append(incident)
        message_index += 1
        if message_index == max_fetch:
            break

    next_run = last_time
    return next_run, incidents


def fetch_incidents_command(client: Client) -> None:
    """
    Function that calls the fetch incidents and writing all incidents to demisto.incidents

    args:
        client (Client): Phisher client
    """
    first_fetch_time = client.first_fetch_time
    fetch_limit = arg_to_number(client.max_fetch)
    next_run, incidents = fetch_incidents(
        client=client,
        last_run=demisto.getLastRun(),
        first_fetch_time=first_fetch_time,
        max_fetch=fetch_limit)  # type: ignore
    demisto.setLastRun({'last_fetch': next_run})
    demisto.incidents(incidents)


''' MAIN FUNCTION '''


def main(params: dict, args: dict, command: str) -> None:
    # get the service API url
    url = urljoin(params.get('url'), 'graphql')  # type: ignore
    if not params.get('apikey') or not (key := params.get('apikey', {}).get('password')):
        raise DemistoException('Missing API Key. Fill in a valid key in the integration configuration.')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    first_fetch_time = arg_to_datetime(params.get('first_fetch')).isoformat()  # type: ignore
    fetch_limit = arg_to_number(params.get('max_fetch'))  # type: ignore
    headers = {
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json'
    }
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            proxy=proxy,
            base_url=url,
            verify=insecure,
            headers=headers,
            first_fetch_time=first_fetch_time,
            max_fetch=fetch_limit
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-incidents':
            fetch_incidents_command(client)
        elif command == 'phisher-message-list':
            return_results(phisher_message_list_command(client, args))
        elif command == 'phisher-create-comment':
            return_results(phisher_create_comment_command(client, args))
        elif command == 'phisher-update-message':
            return_results(phisher_update_message_command(client, args))
        elif command == 'phisher-tags-create':
            return_results(phisher_create_tags_command(client, args))
        elif command == 'phisher-tags-delete':
            return_results(phisher_delete_tags_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main(demisto.params(), demisto.args(), demisto.command())
