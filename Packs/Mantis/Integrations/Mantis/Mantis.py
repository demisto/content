import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

# import json
#
# import dateparser
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TABLE_HEADERS = ['id', 'reporter', 'project', 'category', 'status', 'summary', 'description', 'created_at']


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify=True, proxy=False, headers=None):
        super().__init__(base_url, verify=verify, proxy=False, headers=headers)

    def get_issue(self, _id: str):
        issue = self._http_request(
            method='GET',
            url_suffix='/issues/' + _id
        )
        return issue

    def get_issues(self, params: dict):
        issues = self._http_request(
            method='GET',
            url_suffix='/issues/',
            params=params

        )
        return issues

    def create_issue(self, args):
        body = args
        resp = self._http_request(
            method='POST',
            url_suffix='/issues/',
            json_data=body
        )
        return resp

    def create_note(self, _id, args):
        body = args
        resp = self._http_request(
            method='POST',
            url_suffix=f'/issues/{_id}/notes',
            json_data=body
        )
        return resp

    def close_issue(self, _id):
        body = {
            "status": {
                "name": "closed"
            }
        }
        resp = self._http_request(
            method='PATCH',
            url_suffix=f'/issues/{_id}',
            json_data=body
        )
        return resp


def test_module(client):
    params = {
        "page_size": 1,
        "page": 1
    }
    result = client.get_issues(params)
    if "issues" in result:
        return 'ok'
    else:
        return_error(result)


def create_output_result(resp):
    output = {}
    if isinstance(resp, dict):
        for key, value in resp.items():
            if isinstance(value, dict) and 'name' in value:
                output[key] = value.get('name', "")
            else:
                output[key] = value
    return output


def mantis_get_all_issues_command(client, args):
    """
        Returns list of all  issues for given  args

        Args:
            client (Client): Mantis client.
            args (dict): page filters.

        Returns:
            list of Mantis issues
        """
    if args is not None:
        params = args
        resp = client.get_issues(params=params).get('issues')
        issues = [create_output_result(issue) for issue in resp]
        readable_output = tableToMarkdown("Mantis Issue Details", issues, headers=TABLE_HEADERS)
        results = CommandResults(
            readable_output=readable_output,
            outputs_prefix="Mantis.issue",
            outputs_key_field=TABLE_HEADERS,
            outputs=issues
        )
        return results


def mantis_close_issue_command(client, args):
    _id = args.get("id")
    resp = client.close_issue(_id)
    if 'issues' in resp:
        return f"Issue {_id} has been closed"
    else:
        return_error(resp)


def mantis_get_issue_by_id_command(client, args):
    """
    Returns a mantis issue

    Args:
        client (Client): Mantis client.
        args (dict): all command arguments.
    """
    _id = args.get('id')
    resp_issues = client.get_issue(_id).get('issues')
    resp = {}
    if len(resp_issues) > 0:
        resp = resp_issues[0]
    issues = create_output_result(resp)
    readable_output = tableToMarkdown("Mantis Issue Details", issues, headers=TABLE_HEADERS)

    results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Mantis.issue",
        outputs_key_field=TABLE_HEADERS,
        outputs=issues
    )
    return results


def mantis_create_issue_command(client, args):
    """
        Args:
            body with project details

        Returns:
            Mantis  ticket details
        """
    body = {
        "summary": args.get("summary"),
        "description": args.get("description"),
        "category": {
            "name": args.get("category")
        },
        "project": {
            "name": args.get("project")
        }
    }
    resp = client.create_issue(body).get('issue')
    issues = create_output_result(resp)
    readable_output = tableToMarkdown("Mantis issue created", issues, headers=TABLE_HEADERS)

    results = CommandResults(
        readable_output=readable_output,
        outputs_prefix="Mantis.issue",
        outputs_key_field=TABLE_HEADERS,
        outputs=issues
    )
    return results


def matis_create_note_command(client, args):
    _id = args.get('id')
    body = {
        "text": args.get('text'),
        "view_state": {
            "name": args.get('view_state')
        }
    }
    resp = client.create_note(_id, body)
    if 'note' in resp:
        return 'Note successfully added'
    else:
        return_error(str(resp))


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    token = demisto.params().get('token')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/rest')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)
    headers = {
        "Authorization": token
    }

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers
        )
        args = demisto.args()

        if demisto.command() == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'mantis-get-issue-by-id':
            return_results(mantis_get_issue_by_id_command(client, args))
        elif demisto.command() == 'mantis-get-issues':
            return_results(mantis_get_all_issues_command(client, args))
        elif demisto.command() == 'mantis-create-issue':
            return_results(mantis_create_issue_command(client, args))
        elif demisto.command() == 'mantis-add-note':
            return_results(matis_create_note_command(client, args))
        elif demisto.command() == 'mantis-close-issue':
            return_results(mantis_close_issue_command(client, args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
