import pytest
import os
import json
from Trello import Client, select_outputs, select_outputs_camelize

"""
Test script for the Trello Integration
To test properly, setup a new board with at least one list and pass the ID as environment variable TEST_BOARD.

This test suite runs both unit tests and integration tests

 * Integration tests are run if API_KEY and API_TOKEN are provided
 * Integration tests can save the output of individual calls to ./test_data if GEN_TEST_DATA
 * Unit tests use data from the static JSON test data (appended with _unit) in the ./test_data directory.

Envvars:
    API_TOKEN: If configured, runs integration tests.
    API_KEY: Key assocaited with API token
    TEST_BOARD: ID of Trello board to use as testing ground
    GEN_TEST_DATA: If set, copies the raw output* of the API queries into ./test_data
https://trello.com/app-key
"""

PARAMS = {
    "url": "https://api.trello.com",
    "key": os.getenv("API_KEY"),
    "token": os.getenv("API_TOKEN"),
    "board_id": os.getenv("TEST_BOARD")
}
ARGS = {
    "message": "This is a test alert!"
}

mock_client = Client(
    "false",
    "false",
    base_url="false"
)


def load_json_file(path):
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def testclient():
    """
    Setup a test client, used as a fixture for Integration tests.
    """
    base_url = PARAMS.get("url") + "/1"  # type: ignore[operator]
    client = Client(
        PARAMS.get("key"),
        PARAMS.get("token"),
        base_url=base_url,
    )
    return client


def test_integration_tests(mocker, testclient):
    """
    Retrieves boards
    """
    if not PARAMS.get("token"):
        # Pass if no token for acceptance tests
        return

    test_data = {}
    test_data["list_boards"] = list_boards_tester(testclient)
    test_data["list_lists"] = list_lists_tester(testclient, PARAMS.get("board_id"))
    test_data["list_labels"] = list_labels_tester(testclient, PARAMS.get("board_id"))
    test_list = test_data["list_lists"][0].get("id")

    test_data["create_card"] = create_card_tester(testclient, test_list)
    fetch_tester(testclient, PARAMS.get("board_id"))

    card_id = test_data["create_card"].get("id")

    test_data["update_card"] = update_card_tester(testclient, card_id)
    test_data["add_comment"] = add_comment_tester(testclient, card_id)
    test_data["list_cards"] = list_cards_tester(testclient, test_list)
    test_data["delete_card"] = delete_card_tester(testclient, card_id)
    test_data["list_actions"] = list_actions_tester(testclient, PARAMS.get("board_id"))
    test_data["create_label"] = create_label_tester(testclient, PARAMS.get("board_id"))

    if os.getenv("GEN_TEST_DATA"):
        # If set, test JSON added to test_data
        for k, v in test_data.items():
            with open(f"test_data/{k}.json", "w") as fh:
                json.dump(v, fh, indent=4, sort_keys=True)


def test_select_outputs():
    result = load_json_file("./test_data/list_lists_unit.json")
    outputs = select_outputs(result, ["id", "name", "idBoard"])
    assert len(outputs) == 2
    assert "Id" in outputs[0]


def test_select_outputs_camelize():
    result = load_json_file("./test_data/list_actions_unit.json")
    outputs = select_outputs_camelize(result, ["id", "list_id"])
    assert len(outputs) > 0
    assert "ListId" in outputs[0]


def test_fetch(mocker):
    """
    Test the fetch process
    """
    last_run = {
        "last_fetch": None
    }
    from Trello import fetch_incidents
    lists = load_json_file("./test_data/list_lists_unit.json")
    mocker.patch.object(Client, "list_actions", return_value=load_json_file("./test_data/list_actions_unit.json"))
    mocker.patch.object(Client, "list_lists", return_value=lists)
    mocker.patch.object(Client, "list_cards", return_value=load_json_file("./test_data/list_cards_unit.json"))

    last_run, incidents = fetch_incidents(mock_client, last_run, "blah", "1111")
    # Should not fetch any incidents, as we've passed it a last_id filter which will not match
    assert len(incidents) == 0
    # Now we pass the same command a real list id and we should get at least one result
    last_run, incidents = fetch_incidents(mock_client, last_run, "blah", lists[0].get("id"))
    assert len(incidents) > 0
    assert incidents[0].get("name")
    # Same thing again, except this time we remove the list_id filter
    last_run, incidents = fetch_incidents(mock_client, last_run, "blah", None)  # type: ignore[arg-type]
    assert len(incidents) > 0
    assert incidents[0].get("name")


def test_flatten_actions():
    from Trello import flatten_action_data
    test_actions = load_json_file("./test_data/list_actions_unit.json")
    r = flatten_action_data(test_actions)
    assert (r[0].get("board_id"))
    assert (r[0].get("card_id"))
    assert (r[0].get("list_id"))


def list_boards_tester(testclient):
    from Trello import list_boards

    r = list_boards(testclient)
    assert len(r.raw_response) > 0
    return r.raw_response


def list_lists_tester(testclient, board_id):
    from Trello import list_lists

    r = list_lists(testclient, board_id)
    assert len(r.raw_response) > 0
    return r.raw_response


def create_card_tester(testclient, list_id):
    from Trello import create_card

    list_args = {
        "list_id": "blah",
        "name": "Test card"
    }
    r = create_card(testclient, list_id, list_args)
    assert r.raw_response.get("id")
    return r.raw_response


def list_cards_tester(testclient, list_id):
    from Trello import list_cards

    r = list_cards(testclient, list_id)
    assert len(r.raw_response) > 0
    return r.raw_response


def update_card_tester(testclient, card_id):
    from Trello import update_card

    card_args = {
        "card_id": "blah",
        "desc": "This is an updated card description!"
    }
    r = update_card(testclient, card_id, card_args)
    return r.raw_response


def delete_card_tester(testclient, card_id):
    from Trello import delete_card

    r = delete_card(testclient, card_id)
    return r.raw_response


def list_actions_tester(testclient, board_id):
    from Trello import list_actions

    r = list_actions(testclient, board_id, None, None, None)
    return r.raw_response


def list_labels_tester(testclient, board_id):
    from Trello import list_labels

    r = list_labels(testclient, board_id)
    assert len(r.raw_response) > 0
    return r.raw_response


def create_label_tester(testclient, board_id):
    from Trello import create_label

    args = {
        "name": "Testlabel",
        "color": "green"
    }
    r = create_label(testclient, board_id, args)
    assert len(r.raw_response) > 0
    return r.raw_response


def fetch_tester(testclient, board_id):
    from Trello import fetch_incidents
    last_run = {
        "last_fetch": None
    }
    next_run, incidents = fetch_incidents(testclient, last_run, board_id, None)  # type: ignore[arg-type]
    # First fetch should return something
    assert len(incidents) > 0
    next_run, incidents = fetch_incidents(testclient, next_run, board_id, None)  # type: ignore[arg-type]
    # Second fetch should be empty
    assert len(incidents) == 0


def add_comment_tester(testclient, card_id):
    from Trello import add_comment
    comment_args = {
        "text": "This is a card comment!",
    }
    r = add_comment(testclient, card_id, comment_args)
    return r.raw_response
