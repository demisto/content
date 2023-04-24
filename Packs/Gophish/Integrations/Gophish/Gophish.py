import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import dateparser

# Disable insecure warnings
import urllib3
urllib3.disable_warnings()


def results_return(command, thingtoreturn):
    results = CommandResults(
        outputs_prefix='Gophish.' + str(command),
        outputs_key_field='',
        outputs=thingtoreturn
    )
    return_results(results)


def process_profile_headers(inputtedheaders):
    datalist = []
    datadictionary = {}
    for item in inputtedheaders.split(','):
        data = {}
        data['key'] = item.split(':')[0]
        data['value'] = item.split(':')[1]
        datalist.append(data)
    datadictionary['headers'] = datalist
    return datadictionary


def generate_groups(inputtedgroups):
    list = []
    for item in inputtedgroups.split(','):
        data = {}
        data['name'] = item
        list.append(data)
    return list


def formtargets(targets):
    list = []
    for item in targets.split(':'):
        data = {}
        data['email'] = item.split(',')[0]
        data['first_name'] = item.split(',')[1]
        data['last_name'] = item.split(',')[2]
        data['position'] = item.split(',')[3]
        list.append(data)
    return list


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    Test function gets the base url and if it responds the the test succeeds. No Auth needed.
    """
    result = client._http_request('GET', 'users/')
    if result:
        return 'ok'
    else:
        return 'Test failed ' + str(result)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('apikey')
    headers = {'Authorization': token}

    # get the service API url
    base_url = demisto.params().get('url') + '/api/'

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = BaseClient(
            base_url=base_url,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        # User Management commands
        elif demisto.command() == 'gophish-get-users':
            results_return('Users', client._http_request('GET', 'users/'))
        elif demisto.command() == 'gophish-get-user':
            results_return('User', client._http_request('GET', 'users/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-create-user':
            payload = {'role': demisto.args().get('role'),
                       'password': demisto.args().get('password'),
                       'username': demisto.args().get('username')}
            results_return('NewUser', client._http_request('POST', 'users/', json_data=payload))
        elif demisto.command() == 'gophish-modify-user':
            payload = {'role': demisto.args().get('role'),
                       'password': demisto.args().get('password'),
                       'username': demisto.args().get('username')}
            results_return('ModifiedUser', client._http_request(
                'PUT', 'users/' + str(demisto.args().get('id')), json_data=payload))
        elif demisto.command() == 'gophish-delete-user':
            results_return('DeletedUser', client._http_request('DELETE', 'users/' + str(demisto.args().get('id'))))

        # Sending Profiles commands
        elif demisto.command() == 'gophish-get-all-sending-profiles':
            results_return('AllSendingProfiles', client._http_request('GET', 'smtp/'))
        elif demisto.command() == 'gophish-get-sending-profile':
            results_return('SendingProfile', client._http_request('GET', 'smtp/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-create-sending-profile':
            payload = {'name': demisto.args().get('name'),
                       'interface_type': 'SMTP',
                       'from_address': demisto.args().get('from_address'),
                       'host': demisto.args().get('host'),
                       'username': demisto.args().get('username'),
                       'password': demisto.args().get('password'),
                       'ignore_cert_errors': bool(demisto.args().get('ignore_cert_errors'))}
            if demisto.args().get('headers'):
                profileheaders = process_profile_headers(demisto.args().get('headers'))
                payload.update(profileheaders)
            results_return('CreatedSendingProfile', client._http_request('POST', 'smtp/', json_data=payload))
        elif demisto.command() == 'gophish-delete-sending-profile':
            results_return('DeletedSendingProfile', client._http_request('DELETE', 'smtp/' + str(demisto.args().get('id'))))

        # Landing page commands
        elif demisto.command() == 'gophish-get-all-landing-pages':
            results_return('AllLandingPages', client._http_request('GET', 'pages/'))
        elif demisto.command() == 'gophish-get-landing-page':
            results_return('LandingPage', client._http_request('GET', 'pages/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-create-landing-page':
            payload = {'name': demisto.args().get('name'),
                       'html': demisto.args().get('html'),
                       'capture_credentials': bool(demisto.args().get('capture_credentials')),
                       'capture_passwords': bool(demisto.args().get('capture_passwords')),
                       'redirect_url': demisto.args().get('redirect_url')}
            results_return('CreatedLandingPage', client._http_request('POST', 'pages/', json_data=payload))
        elif demisto.command() == 'gophish-delete-landing-page':
            results_return('DeletedLandingPage', client._http_request('DELETE', 'pages/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-import-site-as-landing-page':
            payload = {'url': demisto.args().get('url'),
                       'include_resources': bool(demisto.args().get('include_resources'))}
            results_return('ImportedSite', client._http_request('POST', 'import/site', json_data=payload))

        # Templates commands
        elif demisto.command() == 'gophish-get-all-templates':
            results_return('AllTemplates', client._http_request('GET', 'templates/'))
        elif demisto.command() == 'gophish-get-template':
            results_return('Template', client._http_request('GET', 'templates/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-delete-template':
            results_return('DeletedTemplate', client._http_request('DELETE', 'templates/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-import-template':
            payload = {'content': demisto.args().get('content'),
                       'convert_links': bool(demisto.args().get('convert_links'))}
            results_return('ImportedTemplate', client._http_request('POST', 'import/email', json_data=payload))
        elif demisto.command() == 'gophish-create-template':
            payload = {'name': demisto.args().get('name'),
                       'subject': demisto.args().get('subject'),
                       'text': demisto.args().get('text'),
                       'html': demisto.args().get('html'),
                       'attachments': []}  # attachments require more work
            results_return('CreatedTemplate', client._http_request('POST', 'templates/', json_data=payload))

        # Campaign commands
        elif demisto.command() == 'gophish-get-all-campaigns':
            results_return('AllCampaigns', client._http_request('GET', 'campaigns/'))
        elif demisto.command() == 'gophish-get-campaign-details':
            results_return('CampaignDetails', client._http_request('GET', 'campaigns/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-get-campaign-results':
            results_return('CampaignResults', client._http_request(
                'GET', 'campaigns/' + str(demisto.args().get('id')) + '/results'))
        elif demisto.command() == 'gophish-get-campaign-summary':
            results_return('CampaignSummary', client._http_request(
                'GET', 'campaigns/' + str(demisto.args().get('id')) + '/summary'))
        elif demisto.command() == 'gophish-delete-campaign':
            results_return('DeletedCampaign', client._http_request('DELETE', 'campaigns/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-complete-campaign':
            results_return('CompletedCampaign', client._http_request(
                'GET', 'campaigns/' + str(demisto.args().get('id')) + '/complete'))
        elif demisto.command() == 'gophish-create-campaign':
            launch_date = dateparser.parse(demisto.args().get('launch_date'))
            assert launch_date is not None, f"could not parse {demisto.args().get('launch_date')}"
            payload = {'name': demisto.args().get('name'),
                       'template': {'name': demisto.args().get('template')},
                       'url': demisto.args().get('url'),
                       'page': {'name': demisto.args().get('page')},
                       'smtp': {'name': demisto.args().get('smtp')},
                       'launch_date': launch_date.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                       'groups': generate_groups(demisto.args().get('groups'))}
            if demisto.args().get('send_by_date'):
                send_by_date = dateparser.parse(demisto.args().get('send_by_date'))
                assert send_by_date is not None
                payload.update({'send_by_date': send_by_date.strftime('%Y-%m-%dT%H:%M:%S+00:00')})
            results_return('CreatedCampaign', client._http_request('POST', 'campaigns/', json_data=payload))

        # User Groups related commands
        elif demisto.command() == 'gophish-get-all-groups':
            results_return('AllGroups', client._http_request('GET', 'groups/'))
        elif demisto.command() == 'gophish-get-group':
            results_return('Group', client._http_request('GET', 'groups/' + str(demisto.args().get('id'))))
        elif demisto.command() == 'gophish-get-all-groups-summary':
            results_return('AllGroupsSummary', client._http_request('GET', 'groups/summary'))
        elif demisto.command() == 'gophish-get-group-summary':
            results_return('GroupSummary', client._http_request('GET', 'groups/' + str(demisto.args().get('id')) + '/summary'))
        elif demisto.command() == 'gophish-create-group':
            payload = {'name': demisto.args().get('name'),
                       'targets': formtargets(demisto.args().get('targets'))}
            results_return('CreatedGroup', client._http_request('POST', 'groups/', json_data=payload))
        elif demisto.command() == 'gophish-delete-group':
            results_return('DeletedGroup', client._http_request('DELETE', 'groups/' + str(demisto.args().get('id'))))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
