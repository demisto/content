import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
from CommonServerUserPython import *

''' IMPORTS '''

import json
import dateparser

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

LIST_BOARDS_SUFFIX = "/members/me/boards"
LISTS_SUFFIX = "/lists"
CARDS_SUFFIX = "/cards"
BOARDS_SUFFIX = "/boards"
ACTIONS = "/actions"
LABELS_SUFFIX = "/labels"
COMMENTS = "/actions/comments"

STANDARD_OUTPUTS = ["id", "name"]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, key, token, **kwargs):
        super(Client, self).__init__(**kwargs)

        self.params = {
            "key": key,
            "token": token
        }

    def list_actions(self, board_id, actions_filter, since=None, before=None):
        """
        Returns all actions associated with a board.
        args

        board_id : str
            ID Of board to list actions of
        filter :
            CSV of action types to filter; https://developer.atlassian.com/cloud/trello/guides/rest-api/action-types/
        """
        params = self.params.copy()
        if actions_filter:
            params["filter"] = actions_filter

        if since:
            params["since"] = since

        if before:
            params["before"] = before

        data = self._http_request(
            method='GET',
            url_suffix=f"{BOARDS_SUFFIX}/{board_id}{ACTIONS}",
            params=params
        )
        return data

    def list_lists(self, board_id):
        """
        Return the lists associated with a board

        """
        data = self._http_request(
            method='GET',
            url_suffix=f"{BOARDS_SUFFIX}/{board_id}{LISTS_SUFFIX}",
            params=self.params
        )
        return data

    def list_boards(self):
        """
        List all the boards visble to this api key/user
        """
        data = self._http_request(
            method='GET',
            url_suffix=f"{LIST_BOARDS_SUFFIX}",
            params=self.params
        )
        return data

    def create_card(self, demisto_args):
        """
        Create a new card
        args

        board_id : str
            ID Of board to create the card in
        list_id
            ID Of list to create the card in
        demisto_args

        name : str
            Name of the card
        desc : str
            Description for the card
        """
        params = {**self.params, **demisto_args}
        demisto.results(params)
        data = self._http_request(
            method='POST',
            url_suffix=f"{CARDS_SUFFIX}",
            params=params
        )
        return data

    def list_cards(self, list_id):
        """
        Returns all cards in a list.
        """
        data = self._http_request(
            method='GET',
            url_suffix=f"{LISTS_SUFFIX}/{list_id}{CARDS_SUFFIX}",
            params=self.params
        )
        return data

    def update_card(self, card_id, demisto_args):
        """
        Update an existing card
        args

        card_id : str
            ID of card to update

        demisto_args
            -- same as create_card --
        """

        params = {**self.params, **demisto_args}
        data = self._http_request(
            method='PUT',
            url_suffix=f"{CARDS_SUFFIX}/{card_id}",
            params=params
        )
        return data

    def add_card_comment(self, card_id, demisto_args):
        """
        Update an existing card
        args

        card_id : str
            ID of card to update

        demisto_args
            -- same as create_card --
        """

        params = {**self.params, **demisto_args}
        data = self._http_request(
            method='POST',
            url_suffix=f"{CARDS_SUFFIX}/{card_id}{COMMENTS}",
            params=params
        )
        return data

    def delete_card(self, card_id):
        """
        Delete a card.
        args

        card_id : str
            ID of card to update

        demisto_args
            -- same as create_card --
        """

        data = self._http_request(
            method='DELETE',
            url_suffix=f"{CARDS_SUFFIX}/{card_id}",
            params=self.params
        )
        return data

    def get_card(self, card_id):
        """
        Get a single card.
        args

        card_id : str
            ID of card
        """

        data = self._http_request(
            method='GET',
            url_suffix=f"{CARDS_SUFFIX}/{card_id}",
            params=self.params
        )
        return data

    def list_labels(self, board_id):
        """
        Return all the labels for a board
        """
        data = self._http_request(
            method='GET',
            url_suffix=f"{BOARDS_SUFFIX}/{board_id}{LABELS_SUFFIX}",
            params=self.params
        )
        return data

    def create_label(self, board_id, demisto_args):
        """
        Create a label to be used on the board
        """
        params = {**self.params, **demisto_args}
        data = self._http_request(
            method='POST',
            url_suffix=f"{BOARDS_SUFFIX}/{board_id}{LABELS_SUFFIX}",
            params=params
        )
        return data


def flatten_action_data(result):
    """
    Given a result of an action query, flatten the result "data"
    """
    flatten_fields = ["id", "name"]
    for action in result:
        data = action.get("data")
        if data:
            for k, v in data.items():
                for f in flatten_fields:
                    if f in v:
                        action[f"{k}_{f}"] = v.get(f)

    return result


def normalise_card_fields(cards):
    """
    Adds XSOAR-like variations of card fields.
    """
    fields = {
        "id": "ID",
        "name": "Name",
        "url": "URL",
        "due": "Due",
        "labels": "Labels"
    }
    for card in cards:
        for k, v in fields.items():
            if k in card:
                card[v] = card[k]

    return cards


def capitalize(word):
    """
    Capitalize JUST the first letter of the string
    """
    word = word.replace(word[0], word[0].capitalize(), 1)
    return word


def select_outputs(result, output_keys):
    """
    Takes a result, either a list or dict, and trims all but the keys specified
    in output_keys

    Capitlizes the result
    """
    if type(result) is dict:
        output = {capitalize(k): result[k] for k in output_keys}
        # output = camelize(output)
        return output
    elif type(result) is list:
        output = []  # type: ignore[assignment]
        for r in result:
            new_r = {capitalize(k): r[k] for k in output_keys}
            output.append(new_r)  # type: ignore[attr-defined]
        return output


def select_outputs_camelize(result, output_keys):
    """
    Takes a result, either a list or dict, and trims all but the keys specified
    in output_keys

    Camelizes any result.
    """
    special_keys = ["card_id", "list_id", "board_id"]
    if type(result) is dict:
        output = {k: result[k] for k in output_keys}
        output = camelize(output, "_")
        return output
    elif type(result) is list:
        output = []
        for r in result:
            new_r = {k: r[k] for k in output_keys}
            # This is a hack to get special keys like card_id into the output when they may or may not exist
            for k in special_keys:
                if k in r:
                    new_r[k] = r[k]

            new_r = camelize(new_r, "_")
            output.append(new_r)
        return output


def list_boards(client):
    result = client.list_boards()
    output_keys = STANDARD_OUTPUTS + ["closed", "dateLastActivity", "url"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.Boards",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Boards", result, headers=["id", "name", "dateLastActivity"]),
        raw_response=result
    )
    return r


def list_lists(client, board_id):
    result = client.list_lists(board_id)
    output_keys = STANDARD_OUTPUTS + ["closed", "idBoard"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.Lists",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Lists", result),
        raw_response=result
    )
    return r


def list_labels(client, board_id):
    result = client.list_labels(board_id)
    output_keys = STANDARD_OUTPUTS + ["color"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.Labels",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Labels", result),
        raw_response=result
    )
    return r


def add_comment(client, card_id, demisto_args):
    result = client.add_card_comment(card_id, demisto_args)
    output_keys = ["id", "date"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.AddedComment",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Comment Added", result),
        raw_response=result
    )
    return r


def list_actions(client, board_id, actions_filter, since, before):
    result = client.list_actions(board_id, actions_filter, since, before)
    result = flatten_action_data(result)
    output_keys = ["id", "type", "date"]
    outputs = select_outputs_camelize(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.Actions",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Actions", result, headers=["id", "type", "date"]),
        raw_response=result
    )
    return r


def create_card(client, list_id, demisto_args):
    del demisto_args["list_id"]
    demisto_args["idList"] = list_id
    result = client.create_card(demisto_args)
    output_keys = STANDARD_OUTPUTS + ["url", "idList"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.CreatedCard",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello created cards", result, headers=["id", "name"]),
        raw_response=result
    )
    return r


def create_label(client, board_id, demisto_args):
    result = client.create_label(board_id, demisto_args)
    output_keys = STANDARD_OUTPUTS
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.CreatedLabel",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Created Label", result),
        raw_response=result
    )
    return r


def list_cards(client, list_id):
    result = client.list_cards(list_id)
    result = normalise_card_fields(result)
    output_keys = STANDARD_OUTPUTS + ["url", "idList", "due", "labels", "desc", "start"]
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.Cards",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Cards", result, headers=STANDARD_OUTPUTS + ["url"]),
        raw_response=result
    )
    return r


def update_card(client, card_id, demisto_args):
    del demisto_args["card_id"]
    result = client.update_card(card_id, demisto_args)
    output_keys = STANDARD_OUTPUTS
    outputs = select_outputs(result, output_keys)
    r = CommandResults(
        outputs_prefix="Trello.UpdatedCard",
        outputs=outputs,
        readable_output=tableToMarkdown("Trello Updated card", result,
                                        headers=["id", "name"] + list(demisto.args().keys())),
        raw_response=result
    )
    return r


def delete_card(client, card_id):
    result = client.delete_card(card_id)
    r = CommandResults(
        outputs_prefix="Trello.DeletedCard",
        outputs=card_id,
        readable_output=f"Deleted card with ID {card_id}",
        raw_response=result
    )
    return r


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    result = client.list_boards()
    if result:
        return 'ok'
    else:
        return "Test failed."


def fetch_incidents(client, last_run: dict, board_id: str, list_id_filter: str):
    """
    This function will execute each interval (default is 1 minute).

    In Trello, this fetches based on the Action API, specifically looking for createCard actions.

    Optionally, the user can specify list_id to only fetch cards in a specific list.

    Args:
        client (Client): Trello Client
        last_run (dict): The most recent fetch

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')
    since = None
    if last_fetch:
        since = last_fetch

    incidents = []
    actions = client.list_actions(board_id, "createCard,updateCard", since)

    actions = flatten_action_data(actions)

    # If we get no actions, means no new actions, simply return.
    if len(actions) == 0:
        return last_run, []

    # Update last run and add incident if the incident is newer than last fetch
    # Most recent action is first element of list
    last_action_id = actions[0].get("id")
    if last_action_id != last_fetch:
        last_fetch = last_action_id

    # Now, we list all the lists on the board
    lists = client.list_lists(board_id)
    cards: List = []
    for list_item in lists:
        list_id = list_item.get("id")
        # Finally, we get all the active cards
        cards_response = client.list_cards(list_id)
        cards = cards + normalise_card_fields(cards_response)

    # If there are no cards on the board, return
    if len(cards) == 0:
        return last_run, []

    new_cards = []
    for action in actions:
        # If it's a new type
        if action.get("type") == "createCard":
            card_id = action.get("card_id")
            if action.get("list_id") == list_id_filter or not list_id_filter:

                for card in cards:
                    if card_id == card.get("id"):
                        card["create_action"] = action
                        new_cards.append(card)
        # If it's updated due to a move
        elif action.get("type") == "updateCard":
            card_id = action.get("card_id")
            # Only support moved (updated) card actions when a list filter is given
            if list_id_filter:
                if action.get("listAfter_id") == list_id_filter:
                    for card in cards:
                        if card_id == card.get("id"):
                            card["create_action"] = action
                            new_cards.append(card)

    for card in new_cards:
        incident_created_time = dateparser.parse(card.get("create_action").get("date"))
        assert incident_created_time is not None, f'could not parse {card.get("create_action").get("date")}'
        incident = {
            'name': card.get("name"),
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(card)
        }

        incidents.append(incident)

    next_run = {'last_fetch': last_fetch}
    return next_run, incidents


def get_mapping_fields():
    fields = {
        "Trello": {
            "id": "str",
            "name": "str",
            "desc": "str"
        }
    }

    return fields


def get_remote_data(client, args):
    parsed_args = GetRemoteDataArgs(args)
    new_incident_data = client.get_card(parsed_args.remote_incident_id)
    demisto.info(f"Calling Remote data fetch for {parsed_args.remote_incident_id}")

    new_incident_data['dbotMirrorInstance'] = demisto.integrationInstance()

    # If the card is closed/archived, add a closeIncident entry
    entries = []
    if new_incident_data.get("closed"):
        demisto.debug('Trello card has been archived.')
        entries.append({
            'Type': EntryType.NOTE,
            'Contents': {
                'dbotIncidentClose': True,
                'closeReason': 'Trello Card archived.'
            },
            'ContentsFormat': EntryFormat.JSON
        })
    return [new_incident_data] + entries


def get_board_id():
    if demisto.args().get("board_id"):
        return demisto.args().get("board_id")

    if demisto.params().get("board_id"):
        return demisto.params().get("board_id")

    raise DemistoException("Could not resolve board_id - please pass as argument or param to integration.")


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    key = demisto.params().get("credentials").get("identifier")
    token = demisto.params().get('credentials').get("password")

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/1')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            key,
            token,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'fetch-incidents':
            board_id = get_board_id()

            # If the list is specified, we only fetch incidents belonging to that list (by ID)
            list_id = demisto.params().get("list_id")

            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                board_id=board_id,
                list_id_filter=list_id
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'trello-list-boards':
            return_results(list_boards(client))
        elif demisto.command() == 'trello-list-lists':
            board_id = get_board_id()
            return_results(list_lists(client, board_id))
        elif demisto.command() == 'trello-list-labels':
            board_id = get_board_id()
            return_results(list_labels(client, board_id))
        elif demisto.command() == 'trello-create-label':
            board_id = get_board_id()
            return_results(create_label(client, board_id, demisto.args()))
        elif demisto.command() == 'trello-list-actions':
            board_id = get_board_id()
            filter_str = demisto.args().get("filter", None)
            since = demisto.args().get("since", None)
            before = demisto.args().get("before", None)
            return_results(list_actions(client, board_id, filter_str, since, before))
        elif demisto.command() == 'trello-create-card':
            list_id = demisto.args().get("list_id")
            return_results(create_card(client, list_id, demisto.args()))
        elif demisto.command() == 'trello-list-cards':
            list_id = demisto.args().get("list_id")
            return_results(list_cards(client, list_id))
        elif demisto.command() == 'trello-update-card':
            card_id = demisto.args().get("card_id")
            return_results(update_card(client, card_id, demisto.args()))
        elif demisto.command() == 'trello-add-comment':
            card_id = demisto.args().get("card_id")
            return_results(add_comment(client, card_id, demisto.args()))
        elif demisto.command() == 'trello-delete-card':
            card_id = demisto.args().get("card_id")
            return_results(delete_card(client, card_id))
        elif demisto.command() == 'trello-get-mapping-fields':
            demisto.results(get_mapping_fields())
        elif demisto.command() == 'trello-get-remote-data':
            demisto.results(get_remote_data(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
