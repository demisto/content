import demistomock as demisto

incident_with_owner = {
    'id': 1,
    'name': 'incident1',
    'owner': 'admin'
}
incident_without_owner = {
    'id': 2,
    'name': 'incident2',
    'owner': ""
}


def test_get_owner_email(mocker):
    """
    Given:
        - Incident with owner.
    When:
        - Running get_owner_email function.
    Then:
        - Validating the return value as expected.
    """
    from SendEmailOnSLABreach import get_owner_email

    mocker.patch.object(demisto, 'incidents', return_value=[incident_with_owner])
    mocker.patch.object(demisto, "executeCommand", return_value=[{'EntryContext':
                                                                 {'UserByUsername': {'email': "test@gmail.com"}},
                                                                  'Type': ''}])
    results_mock = mocker.patch.object(demisto, 'results')
    assert get_owner_email() == "test@gmail.com"
    results_mock.assert_not_called()


def test_get_no_email_owner(mocker):
    """
    Given:
        - Incident without owner.
    When:
        - Running get_owner_email function.
    Then:
        - Validating calling to 'demisto.results' once with the right arguments.
    """
    from SendEmailOnSLABreach import get_owner_email

    mocker.patch.object(demisto, 'incidents', return_value=[incident_without_owner])
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    get_owner_email()
    demisto_results_mocker.assert_called_once()
    results = demisto_results_mocker.call_args[0][0]
    assert results == {"Type": 4,
                       "ContentsFormat": "text",
                       "Contents": "An email can't be sent to the owner of the incident,"
                                   " because no owner was assigned."}


def test_get_subject(mocker):
    """
    Given:
        - Incident
    When:
        - Running get_subject function.
    Then:
        - Validating the return value as expected.
    """
    from SendEmailOnSLABreach import get_subject

    mocker.patch.object(demisto, 'incidents', return_value=[incident_with_owner])
    excepted_subject = "SLA Breached in incident \"{}\" #{}".format(incident_with_owner['name'],
                                                                    incident_with_owner['id'])
    assert get_subject() == excepted_subject


def test_send_email(mocker):
    """
    Given:
        - The function's arguments
    When:
        - Running send_email function.
    Then:
         - Validating calling to 'demisto.results' once with the right arguments.
    """
    from SendEmailOnSLABreach import send_email
    mocker.patch.object(demisto, "executeCommand", return_value="send-mail")
    results_mock = mocker.patch.object(demisto, 'results')
    send_email(to="to_mail_test", subject="subject_test", body="body_test")
    results_mock.assert_called_once()
    assert results_mock.call_args[0][0] == "send-mail"


def test_get_body(mocker):
    """
    Given:
        - The function's arguments
    When:
        - Running get_body function.
    Then:
        - Validating the return value as expected.
    """
    from SendEmailOnSLABreach import get_body
    field_name, sla, start_date = "cliNameTest", "slaTest", "2022-09-07T15:10:04.000Z"
    args = {'field': {'cliName': "cliNameTest"}, 'fieldValue': {"sla": "slaTest",
                                                                "startDate": "2022-09-07T15:10:04.000Z"}}
    mocker.patch.object(demisto, 'args', return_value=args)
    excepted_body = "We have detected a breach in your SLA \"{}\".\nThe SLA was set to {} minute and was started on {}." \
        .format(field_name, sla, start_date.split(".")[0])
    assert get_body() == excepted_body
