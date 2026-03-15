import json


from DarktraceEmail import Client, get_email_command, release_email_command, hold_email_command, fetch_incidents


"""*****HELPER FUNCTIONS****"""


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


"""*****TEST FUNCTIONS****"""


def test_get_email(requests_mock):
    """
    Given
            Integration queries Darktrace Email for single email
    When
            Calling the darktrace-email-get-email command with a specific email UUID
    Then
            Email object is returned
    """
    uuid = "BA13B274-03F3-46D6-8698-244DFF1037A0.1"

    mock_api_response = util_load_json("test_data/get_email.json")
    requests_mock.get(f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid}", json=mock_api_response)

    mock_api_response_tags = util_load_json("test_data/get_tags.json")
    requests_mock.get("https://mock.darktrace.com/agemail/api/v1.0/resources/tags", json=mock_api_response_tags)

    client = Client(base_url="https://mock.darktrace.com", verify=False, auth=("examplepub", "examplepri"))
    client.get_tag_mapper()

    integration_response = get_email_command(client, args={"uuid": uuid})
    expected_response = util_load_json("test_data/formatted_get_email.json")

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == "Darktrace.Email"
    assert integration_response.outputs_key_field == "uuid"


def test_release_email(requests_mock):
    """
    Given
            Integration attempts to release an email that has been held
    When
            Calling the darktrace-email-release-email command with a specific email UUID
    Then
            Response to release request is returned
    """
    uuid = "BA13B274-03F3-46D6-8698-244DFF1037A0.1"
    recipient = "leeroy.jenkins@example.com"

    mock_api_response = util_load_json("test_data/release_email.json")
    requests_mock.post(f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid}/action", json=mock_api_response)

    client = Client(base_url="https://mock.darktrace.com", verify=False, auth=("examplepub", "examplepri"))

    integration_response = release_email_command(client, args={"uuid": uuid, "recipient": recipient})
    expected_response = util_load_json("test_data/formatted_release_email.json")

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == "Darktrace.Action"
    assert integration_response.outputs_key_field == "resp"


def test_hold_email(requests_mock):
    """
    Given
            Integration attempts to hold an email
    When
            Calling the darktrace-email-hold-email command with a specific email UUID
    Then
            Response to hold request is returned
    """
    uuid = "BA13B274-03F3-46D6-8698-244DFF1037A0.1"
    recipient = "leeroy.jenkins@example.com"

    mock_api_response_get_email = util_load_json("test_data/get_email.json")
    requests_mock.get(f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid}", json=mock_api_response_get_email)

    mock_api_response = util_load_json("test_data/hold_email.json")
    requests_mock.post(f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid}/action", json=mock_api_response)

    client = Client(base_url="https://mock.darktrace.com", verify=False, auth=("examplepub", "examplepri"))

    integration_response = hold_email_command(client, args={"uuid": uuid, "recipient": recipient})
    expected_response = util_load_json("test_data/formatted_hold_email.json")

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == "Darktrace.Action"
    assert integration_response.outputs_key_field == "resp"


def test_fetch_incidents(requests_mock):
    """
    Given
            Integration pulls in incidents from ASM
    When
            Regular interval defined by user, default is one minute
    Then
            Incident info will be formatted for XSOAR UI and required info for next call will be returned
    """
    uuid_01 = "74AADFDC-33A9-4065-ACFC-B2493E8722BF.1"
    uuid_02 = "8EEFBFA4-6CA2-4306-B688-BA6B9F60AEEF.1"

    mock_api_response_incident_01 = util_load_json("test_data/incident_01.json")
    requests_mock.get(
        f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid_01}?dtime=1744300527341", json=mock_api_response_incident_01
    )

    mock_api_response_incident_02 = util_load_json("test_data/incident_02.json")
    requests_mock.get(
        f"https://mock.darktrace.com/agemail/api/v1.0/emails/{uuid_02}?dtime=1744300434119", json=mock_api_response_incident_02
    )

    mock_api_response_get_email = util_load_json("test_data/fetch_incidents.json")
    requests_mock.post("https://mock.darktrace.com/agemail/api/v1.0/emails/search", json=mock_api_response_get_email)

    mock_api_response_tags = util_load_json("test_data/get_tags.json")
    requests_mock.get("https://mock.darktrace.com/agemail/api/v1.0/resources/tags", json=mock_api_response_tags)

    client = Client(base_url="https://mock.darktrace.com", verify=False, auth=("examplepub", "examplepri"))
    client.get_tag_mapper()

    last_run = {
        "last_fetch": 1598932817000  # Mon, Aug 31, 2020 9 PM Pacific
    }

    _, integration_response = fetch_incidents(
        client,
        max_alerts=20,
        last_run=last_run,
        first_fetch_time="1 day ago",
        min_score=20,
        tag_severity=["Critical", "Warning", "Informational"],
        actioned=False,
        direction=False,
    )

    expected_response = util_load_json("test_data/formatted_fetch_incidents.json")

    assert integration_response == expected_response
    assert len(integration_response) == 2
