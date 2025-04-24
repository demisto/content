import demistomock as demisto

HTTP_REQUEST_MOCK = {
    "ServiceRequestId": "ServiceRequestId",
    "ServiceRequestStatus": "ServiceRequestStatus",
    "Priority": "Priority",
    "Created": {"When": {"Time": "Time", "Date": "Date"}},
    "Details": "Details",
    "SourceReference": "SourceReference",
    "RequesterContactInformation": {
        "RequesterEmail": "RequesterEmail",
        "RequesterPhone": "RequesterPhone",
        "RequesterName": "RequesterName",
        "RequesterWorkStreet": "RequesterWorkStreet",
        "RequesterWorkLocation": "RequesterWorkLocation",
        "RequesterWorkCity": "RequesterWorkCity",
        "ContactInformation": {"ContactEmail": "ContactEmail", "ContactPhone": "ContactPhone", "ContactName": "ContactName"},
    },
}

REQUEST_ARGS_MOCK = {
    "details": "details",
    "requester_ntid": "requester_ntid",
    "requester_pernr": "requester_pernr",
    "contact_email": "contact_email",
    "contact_name": "contact_name",
    "contact_phone": "contact_phone",
    "requester_email": "requester_email",
    "requester_name": "requester_name",
    "requester_phone": "requester_phone",
    "requester_work_city": "requester_work_city",
    "requester_work_location": "requester_work_location",
    "requester_work_street": "requester_work_street",
}


def test_remedy_get_ticket_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a remedy_get_ticket_command normally.
    Then:  ensures the expected result is returned
    """

    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"server": "server", "xml_ns": "xml_ns", "username": "username", "password": "password"}
    )
    mocker.patch.object(demisto, "args", return_value={"service_request_id": "service_request_id"})

    import remedy_SR

    mocker.patch.object(
        remedy_SR, "http_request", return_value={"Envelope": {"Body": {"getResponse": {"return": {"Body": HTTP_REQUEST_MOCK}}}}}
    )

    remedy_SR.remedy_get_ticket_command()

    assert "### Ticket:" in demisto.results.call_args_list[0][0][0].get("HumanReadable")


def test_remedy_create_ticket_command(mocker):
    """
    Given: Demisto args and params.
    When:  Running a create_ticket_command normally.
    Then:  ensures the expected result is returned
    """
    mocker.patch.object(demisto, "results")
    mocker.patch.object(
        demisto, "params", return_value={"server": "server", "xml_ns": "xml_ns", "username": "username", "password": "password"}
    )
    mocker.patch.object(demisto, "args", return_value=REQUEST_ARGS_MOCK)

    import remedy_SR

    mocker.patch.object(
        remedy_SR,
        "http_request",
        return_value={"Envelope": {"Body": {"createResponse": {"return": {"Body": HTTP_REQUEST_MOCK}}}}},
    )

    remedy_SR.remedy_create_ticket_command()

    assert "### Ticket:" in demisto.results.call_args_list[0][0][0].get("HumanReadable")
