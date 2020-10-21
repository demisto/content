import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''


# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


INTEGRATION_NAME = 'GitLab'


'''API Client'''


class Client(BaseClient):

    def query(self, suffix, response_type="json", method="GET", body=None):
        suffix = suffix
        LOG(f'running request with url= {self._base_url}')

        res = self._http_request(
            method=method,
            url_suffix=suffix,
            resp_type=response_type,
            data=body
        )
        return res


'''' Commands '''


def test_module(client):
    test_result=client.query(suffix='/version')
    if test_result.get('version'):
        return "ok"
    else:
        return "Test Failed:" + test_result


def get_project_by_url(client, args):
    search_query = '/projects/' + args.get('provider') + '/' + args.get('org') + '/' + args.get('name')
    title = f'{INTEGRATION_NAME} - Project Details'
    raws = []
    project_ec = []
    raw_response = client.query(search_query)

    if raw_response:
        raws.append(raw_response)
        project_ec.append({
            "id": raws[0]['id'],
            "name": raws[0]['name'],
            "url": raws[0]['url'],
            "languages": raws[0]['languages']
        })

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Projects": project_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Projects'], name=title)
    return [human_readable, context_entry, raws]


def get_project_by_id(client, args):
    search_query = '/projects/' + str(args.get('id'))
    title = f'{INTEGRATION_NAME} - Project Details'
    raws = []
    project_ec = []
    raw_response = client.query(search_query)

    if raw_response:
        raws.append(raw_response)
        project_ec.append({
            "id": raws[0]['id'],
            "name": raws[0]['name'],
            "url": raws[0]['url'],
            "languages": raws[0]['languages']
        })

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Projects": project_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Projects'], name=title)
    return [human_readable, context_entry, raws]


def get_project_config(client, args):
    search_query = '/projects/' + str(args.get('id')) + '/settings/analysis-configuration'
    title = f'{INTEGRATION_NAME} - Project LGTM Configurations'
    raws = []
    project_ec = []
    raw_response = client.query(search_query, response_type='text')

    if raw_response:
        raws.append(raw_response)
        project_ec.append(raws)

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Configs": project_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Configs'], name=title, headers='Configurations')
    return [human_readable, context_entry, raws]


def run_commit_analysis(client, args):
    search_query = '/analyses/' + str(args.get('project_id')) + \
                   '?commit=' + args.get('commit_id') + \
                   '&language=' + args.get('language')
    title = f'{INTEGRATION_NAME} - Code Analysis Results'
    raws = []
    analysis_ec = []
    raw_response = client.query(search_query, method="POST")['task-result']

    if raw_response:
        raws.append(raw_response)
        analysis_ec.append(raws)

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Analysis": analysis_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Analysis'], name=title, headers='Analysis Results')
    return [human_readable, context_entry, raws]


def get_analysis_status(client, args):
    analysis_id = args.get('analysis_id')
    commit_id = args.get('commit_id')
    project_id = args.get('project_id')

    if analysis_id:
        search_query = '/analyses/' + str(analysis_id)
        title = f'{INTEGRATION_NAME} - Code Analysis Status'
        raws = []
        analysis_ec = []
        raw_response = client.query(search_query)

        if raw_response:
            raws.append(raw_response)
            analysis_ec.append(raws[0])

        if not raws:
            return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')
        human_readable = tableToMarkdown(t=analysis_ec[0]['languages'][0]['status'], name=title, headers='Analysis Status')
        return [human_readable, {"LGTM.Analysis(val.id == obj.id)": analysis_ec}, raws]

    elif commit_id and project_id:
        search_query = '/analyses/' + str(project_id) + '/commits/' + str(commit_id)
        title = f'{INTEGRATION_NAME} - Code Analysis Status'
        raws = []
        analysis_ec = []
        raw_response = client.query(search_query)

        if raw_response:
            raws.append(raw_response)
            analysis_ec.append(raws[0])

        if not raws:
            return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')
        human_readable = tableToMarkdown(t=analysis_ec[0]['languages'][0]['status'], name=title, headers='Analysis Status')
        return [human_readable, {"LGTM.Analysis(val.id == obj.id)": analysis_ec}, raws]

    else:
        return_error(f'{INTEGRATION_NAME} - Please use either the Analysis ID or Commit and Project IDs')


def get_alerts_details(client, args):
    search_query = '/analyses/' + str(args.get('analysis_id')) + '/alerts?excluded-files=false'
    title = f'{INTEGRATION_NAME} - Code Analysis Alerts'
    raws = []
    analysis_ec = []
    raw_response = client.query(search_query)

    if raw_response:
        raws.append(raw_response)

    for runs in raws[0]['runs']:
        for result in runs['results']:
            analysis_ec.append({
                'analysisId': args.get('analysis_id'),
                'alert': result
            })

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Alerts": analysis_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Alerts'], name=title)
    return [human_readable, context_entry, raws]


def run_project_query(client, args):
    search_query = '/queryjobs/' + \
                   '?language=' + args.get('language') + \
                   '&project-id=' + str(args.get('project_id'))
    title = f'{INTEGRATION_NAME} - Query Analysis Results'
    raws = []
    query_ec = []

    raw_response = client.query(search_query, method="POST", body=args.get('query'))

    if raw_response:
        raws.append(raw_response)
        query_ec.append(raws)

    if not raws:
        return_error(f'{INTEGRATION_NAME} - Could not find any results for given query')

    context_entry = {
        "LGTM": {"Queries": query_ec}
    }

    human_readable = tableToMarkdown(t=context_entry['LGTM']['Queries'], name=title, headers='Query Results')
    return [human_readable, context_entry, raws]


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('apikey')
    base_url = params['url'][:-1] if (params['url'] and params['url'].endswith('/')) else params['url'] + '/api/v4'
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            ok_codes=(200, 201, 202, 204),
            headers={
                'PRIVATE-TOKEN': api_key,
                'Content-Type': 'text/plain'
            },
        )

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_outputs(result)

        elif demisto.command() == 'lgtm-get-project-by-url':
            result = get_project_by_url(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-get-project-by-id':
            result = get_project_by_id(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-get-project-config':
            result = get_project_config(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-run-commit-analysis':
            result = run_commit_analysis(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-get-analysis-status':
            result = get_analysis_status(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-get-alerts-details':
            result = get_alerts_details(client, demisto.args())
            return_outputs(*result)

        elif demisto.command() == 'lgtm-run-project-query':
            result = run_project_query(client, demisto.args())
            return_outputs(*result)

    except Exception as e:
        return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
