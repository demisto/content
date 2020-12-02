import dateparser
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from requests_oauthlib import OAuth1

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''


ISSUE_SCHEMA = {
    "aggregateprogress": {
        "progress": 144000,
        "total": 144000,
        "percent": 100
    },
    "aggregatetimeestimate": 0,
    "aggregatetimeoriginalestimate": None,
    "aggregatetimespent": 144000,
    "assignee": {
        "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
        "accountId": "5d4147974125b20c3159b11d",
        "emailAddress": "drwho@atlassian.net",
        "avatarUrls": {
            "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2Favatar-"
                     "management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
        },
        "displayName": "Dr Who",
        "active": True,
        "timeZone": "Etc/GMT",
        "accountType": "atlassian"
    },
    "attachment": [{
        "id": 10000,
        "self": "https://your-domain.atlassian.net/rest/api/3/attachments/10000",
        "filename": "picture.jpg",
        "author": {
            "self": "https://your-domain.atlassian.net/rest/api/3/user?accountId=5b10a2844c20165700ede21g",
            "key": ",",
            "accountId": "5b10a2844c20165700ede21g",
            "name": ",",
            "avatarUrls": {
                "48x48": "https://avatar-management--avatars.server-location.prod.public.atl-paas.net/initials/"
                         "MK-5.png?size=48&s=48"
            },
            "displayName": "Mia Krystof",
            "active": False
        },
        "created": "2020-08-18T02:30:10.001+0000",
        "size": 23123,
        "mimeType": "image/jpeg",
        "content": "https://your-domain.atlassian.net/jira/secure/attachments/10000/picture.jpg",
        "thumbnail": "https://your-domain.atlassian.net/jira/secure/thumbnail/10000/picture.jpg"
    }],
    "comment": {
        "comments": [{
            "self": "https://your-server.atlassian.net/rest/api/2/issue/10000/comment/10005",
            "id": "10005",
            "author": {
                "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
                "accountId": "5d4147974125b20c3159b11d",
                "emailAddress": "drwho@atlassian.net",
                "avatarUrls": {
                    "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2F"
                             "avatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
                },
                "displayName": "Dr Who",
                "active": True,
                "timeZone": "Etc/GMT",
                "accountType": "atlassian"
            },
            "body": "This is the Comment",
            "updateAuthor": {
                "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
                "accountId": "5d4147974125b20c3159b11d",
                "emailAddress": "drwho@atlassian.net",
                "avatarUrls": {
                    "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2F"
                             "avatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
                },
                "displayName": "Dr Who",
                "active": True,
                "timeZone": "Etc/GMT",
                "accountType": "atlassian"
            },
            "created": "2020-08-18T16:38:01.900+0000",
            "updated": "2020-08-18T16:38:01.900+0000",
            "jsdPublic": False
        }],
        "maxResults": 1,
        "total": 1,
        "startAt": 0
    },
    "components": [],
    "created": "2020-08-18T13:31:56.249+0000",
    "creator": {
        "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
        "accountId": "5d4147974125b20c3159b11d",
        "emailAddress": "drwho@atlassian.net",
        "avatarUrls": {
            "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2Favatar-"
                     "management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
        },
        "displayName": "Dr Who",
        "active": True,
        "timeZone": "Etc/GMT",
        "accountType": "atlassian"
    },
    "description": "You are now looking at an issue in one of your preset queues. This is where your agents work on "
                   "your end users' requests.\n\nOn your left hand side are the queues where you can easily see "
                   "all requests coming from your end users.\n\nGot it? Now change the workflow status and add a "
                   "comment to resolve this request.",
    "duedate": None,
    "environment": None,
    "expand": "renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations,customfield_"
              "10042.serviceName",
    "fixVersions": [],
    "id": "10000",
    "issuelinks": [],
    "issuerestriction": {
        "issuerestrictions": {},
        "shouldDisplay": False
    },
    "issuetype": {
        "self": "https://your-server.atlassian.net/rest/api/2/issuetype/10005",
        "id": "10005",
        "description": "A request that follows ITSM workflows.",
        "iconUrl": "https://your-server.atlassian.net/secure/viewavatar?size=medium&avatarId=10552&"
                   "avatarType=issuetype",
        "name": "Service Request",
        "subtask": False,
        "avatarId": 10552
    },
    "key": "IST-1",
    "labels": [],
    "lastViewed": "2020-08-18T16:36:09.246+0000",
    "priority": {
        "self": "https://your-server.atlassian.net/rest/api/2/priority/2",
        "iconUrl": "https://your-server.atlassian.net/images/icons/priorities/high.svg",
        "name": "High",
        "id": "2"
    },
    "progress": {
        "progress": 144000,
        "total": 144000,
        "percent": 100
    },
    "project": {
        "self": "https://your-server.atlassian.net/rest/api/2/project/10001",
        "id": "10001",
        "key": "IST",
        "name": "IT Service Test",
        "projectTypeKey": "service_desk",
        "simplified": False,
        "avatarUrls": {
            "48x48": "https://your-server.atlassian.net/secure/projectavatar?pid=10001&avatarId=10411"
        }
    },
    "reporter": {
        "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=qm%3A5a82b573-3fb7-472b-9ecc-"
                "5ab90388d8be%3A72e66569-cae7-433b-8b6d-c4109f0f7aae",
        "accountId": "qm:5a82b573-3fb7-472b-9ecc-5ab90388d8be:72e66569-cae7-433b-8b6d-c4109f0f7aae",
        "emailAddress": "example@atlassian-demo.invalid",
        "avatarUrls": {
            "48x48": "https://avatar-management--avatars.us-west-2.prod.public.atl-paas.net/default-avatar.png"
        },
        "displayName": "Example Customer",
        "active": True,
        "timeZone": "Etc/GMT",
        "accountType": "customer"
    },
    "resolution": None,
    "resolutiondate": None,
    "security": None,
    "self": "https://your-server.atlassian.net/rest/api/latest/issue/10000",
    "status": {
        "self": "https://your-server.atlassian.net/rest/api/2/status/10005",
        "description": "This was auto-generated by Jira Service Desk during workflow import",
        "iconUrl": "https://your-server.atlassian.net/images/icons/status_generic.gif",
        "name": "Waiting for customer",
        "id": "10005",
        "statusCategory": {
            "self": "https://your-server.atlassian.net/rest/api/2/statuscategory/4",
            "id": 4,
            "key": "indeterminate",
            "colorName": "yellow",
            "name": "In Progress"
        }
    },
    "statuscategorychangedate": "2020-08-18T13:31:56.619+0000",
    "sub-tasks": [{
        "id": "10000",
        "type": {
            "id": "10000",
            "name": ",",
            "inward": "Parent",
            "outward": "Sub-task"
        },
        "outwardIssue": {
            "id": "10003",
            "key": "ED-2",
            "self": "https://your-domain.atlassian.net/rest/api/3/issue/ED-2",
            "fields": {
                "status": {
                    "iconUrl": "https://your-domain.atlassian.net/images/icons/statuses/open.png",
                    "name": "Open"
                }
            }
        }
    }],
    "subtasks": [],
    "summary": "What am I looking at?",
    "timeestimate": 0,
    "timeoriginalestimate": None,
    "timespent": 144000,
    "timetracking": {
        "remainingEstimate": "0m",
        "timeSpent": "1w",
        "remainingEstimateSeconds": 0,
        "timeSpentSeconds": 144000
    },
    "updated": "2020-08-18T16:43:41.225+0000",
    "versions": [],
    "votes": {
        "self": "https://your-server.atlassian.net/rest/api/2/issue/IST-1/votes",
        "votes": 0,
        "hasVoted": False
    },
    "watcher": {
        "self": "https://your-domain.atlassian.net/rest/api/3/issue/EX-1/watchers",
        "isWatching": False,
        "watchCount": 1,
        "watchers": [{
            "self": "https://your-domain.atlassian.net/rest/api/3/user?accountId=5b10a2844c20165700ede21g",
            "accountId": "5b10a2844c20165700ede21g",
            "displayName": "Mia Krystof",
            "active": False
        }]
    },
    "watches": {
        "self": "https://your-server.atlassian.net/rest/api/2/issue/IST-1/watchers",
        "watchCount": 1,
        "isWatching": True
    },
    "worklog": {
        "startAt": 0,
        "maxResults": 20,
        "total": 1,
        "worklogs": [{
            "self": "https://your-server.atlassian.net/rest/api/2/issue/10000/worklog/10000",
            "author": {
                "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
                "accountId": "5d4147974125b20c3159b11d",
                "emailAddress": "drwho@atlassian.net",
                "avatarUrls": {
                    "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2F"
                             "avatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
                },
                "displayName": "Dr Who",
                "active": True,
                "timeZone": "Etc/GMT",
                "accountType": "atlassian"
            },
            "updateAuthor": {
                "self": "https://your-server.atlassian.net/rest/api/2/user?accountId=5d4147974125b20c3159b11d",
                "accountId": "5d4147974125b20c3159b11d",
                "emailAddress": "drwho@atlassian.net",
                "avatarUrls": {
                    "48x48": "https://secure.gravatar.com/avatar/f5b796a9a312e4b61ef25a448dfc6207?d=https%3A%2F%2F"
                             "avatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FAB-6.png"
                },
                "displayName": "Dr Who",
                "active": True,
                "timeZone": "Etc/GMT",
                "accountType": "atlassian"
            },
            "comment": "This is a worklog",
            "created": "2020-08-18T14:29:36.277+0000",
            "updated": "2020-08-18T14:29:36.277+0000",
            "started": "2020-08-16T22:29:23.576+0000",
            "timeSpent": "1w",
            "timeSpentSeconds": 144000,
            "id": "10000",
            "issueId": "10000"
        }]
    },
    "workratio": -1
}


''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url=None, mirroring=None, tag_internal='internal_note', tag_public='public_note',
                 username=None, password=None, api_token=None, consumer_key=None,
                 access_token=None, private_key=None, query='', id_offset=0,
                 verify=False, proxy=None, headers={}):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)
        self.mirror_direction = mirroring
        self.tag_internal = tag_internal
        self.tag_public = tag_public
        self.username = username
        self.password = password
        self.api_token = api_token
        self.consumer_key = consumer_key
        self.access_token = access_token
        self.private_key = private_key
        self.query = query
        self.id_offset = id_offset
        self.instance_name = demisto.integrationInstance()
        self.auth = self.get_auth()

    def generate_basic_oauth(self):
        return self.username, (self.api_token or self.password)

    def generate_oauth1(self, method=None, resource=None):
        oauth = OAuth1(
            client_key=self.consumer_key,
            rsa_key=self.private_key,
            signature_method=method,
            resource_owner_key=resource
        )
        return oauth

    def get_auth(self):
        is_basic = self.username and (self.password or self.api_token)
        is_oauth1 = self.consumer_key and self.access_token and self.private_key

        if is_basic:
            return self.generate_basic_oauth()

        elif is_oauth1:
            self._headers.update({'X-Atlassian-Token': 'nocheck'})
            return self.generate_oauth1()

        return_error(
            'Please provide the required Authorization information:'
            '- Basic Authentication requires user name and password or API token'
            '- OAuth 1.0 requires ConsumerKey, AccessToken and PrivateKey'
        )

    def run_query(self, query=None, start_at=0, max_results=50):
        query_params = {
            'jql': query if query else self.query,
            "startAt": start_at,
            "maxResults": max_results,
        }
        result = self._http_request(
            'GET',
            '/rest/api/latest/search',
            params=query_params,
            auth=self.auth,
            resp_type='json'
        )
        if "issues" in result:
            return result
        errors = ",".join(result.get("errorMessages", ['could not fetch any issues, please check your query']))
        if 'could not fetch any issues, please check your query' in errors:
            return {}
        return_error(f'No issues were found, error message from Jira: {errors}')

    def fetch_incidents(self, query=None, start_at=0, max_results=50):
        query_params = {
            'jql': query if query else self.query,
            "startAt": start_at,
            "maxResults": max_results,
        }
        result = self._http_request(
            'GET',
            '/rest/api/latest/search',
            params=query_params,
            auth=self.auth,
            resp_type='json'
        )
        if "issues" in result:
            return result
        else:
            return {}

    def get_issue(self, issue_id):
        res = self._http_request(
            'GET',
            f'/rest/api/latest/issue/{issue_id}',
            auth=self.auth,
            ok_codes=[200, 404],
            resp_type='response'
        )
        if res.status_code == 200:
            return res.json()
        else:
            demisto.error(f'Error with get_issue: {res.json()}')
            return {}

    def upload_file(self, entry_id, issue_id, attachment_name=None):
        self._headers = {'X-Atlassian-Token': 'no-check'}
        file_name, file_bytes = get_file(entry_id)
        res = self._http_request(
            'POST',
            f'rest/api/latest/issue/{issue_id}/attachments',
            files={'file': (attachment_name or file_name, file_bytes)},
            headers=self._headers,
            auth=self.auth,
        )
        return res

    def add_comment(self, issue_id, comment, visibility, internal):
        data = {
            "body": comment
        }

        if visibility:
            data["visibility"] = {
                "type": "role",
                "value": visibility
            }
        data['properties'] = [{
            "key": "sd.public.comment",
            "value": {
                "internal": True if internal else False
            }
        }]
        res = self._http_request(
            'POST',
            f'rest/api/latest/issue/{issue_id}/comment',
            auth=self.auth,
            data=json.dumps(data),
            resp_type='json'
        )
        return res

    def add_link(self, issue_id=None, title=None, url=None, summary=None,
                 global_id=None, relationship=None, application_type=None,
                 application_name=None):
        link = {"object": {"url": url, "title": title}}
        if summary:
            link['summary'] = summary
        if global_id:
            link['globalId'] = global_id
        if relationship:
            link['relationship'] = relationship
        if application_type or application_name:
            link['application'] = {}
        if application_type:
            link['application']['type'] = application_type
        if application_type:
            link['application']['name'] = application_name
        res = self._http_request(
            'POST',
            f'rest/api/latest/issue/{issue_id}/remotelink',
            data=json.dumps(link),
            auth=self.auth,
            resp_type='json'
        )
        return res

    def edit_issue(self, issue_id, issue={}):
        res = self._http_request(
            'PUT',
            f'rest/api/latest/issue/{issue_id}',
            data=json.dumps(issue),
            auth=self.auth,
            resp_type='response'
        )
        return res

    def edit_status(self, issue_id, status):
        j_res = self._http_request(
            'GET',
            f'rest/api/2/issue/{issue_id}/transitions',
            auth=self.auth,
            resp_type='json'
        )
        transitions = [transition.get('name') for transition in j_res.get('transitions', {})]
        for i, transition in enumerate(transitions):
            if transition.lower() == status.lower():
                json_body = {"transition": {"id": str(j_res.get('transitions')[i].get('id'))}}
                res = self._http_request(
                    'POST',
                    f'rest/api/latest/issue/{issue_id}/transitions?expand=transitions.fields',
                    data=json.dumps(json_body),
                    auth=self.auth,
                    resp_type='response'
                )
                return res
        return_error(f'Status "{status}" not found. \nValid transitions are: {transitions} \n')

    def get_comments(self, issue_id, params=None):
        res = self._http_request(
            'GET',
            f'rest/api/latest/issue/{issue_id}/comment',
            resp_type='json',
            auth=self.auth,
            params=params
        )
        return res

    def get_worklog(self, issue_id, params=None):
        res = self._http_request(
            'GET',
            f'rest/api/latest/issue/{issue_id}/worklog',
            resp_type='json',
            auth=self.auth,
            params=params
        )
        return res

    def delete_issue(self, issue_id):
        res = self._http_request(
            'DELETE',
            f'rest/api/latest/issue/{issue_id}',
            auth=self.auth,
            resp_type='response'
        )
        return res

    def get_download(self, full_url):
        res = self._http_request(
            'GET',
            '',
            full_url=full_url,
            resp_type='response',
            auth=self.auth,
            headers={}
        )
        return res.content

    def expand_url(self, url):
        res = self._http_request(
            'GET',
            '',
            full_url=url,
            resp_type='json',
            auth=self.auth
        )
        return res


''' HELPER FUNCTIONS '''


def get_file(entry_id):
    get_file_path_res = demisto.getFilePath(entry_id)
    file_path = get_file_path_res["path"]
    file_name = get_file_path_res["name"]
    with open(file_path, 'rb') as f:
        file_bytes = f.read()
    return file_name, file_bytes


def generate_md_context_get_issue(data):
    get_issue_obj: dict = {"md": [], "context": []}
    if not isinstance(data, list):
        data = [data]

    for element in data:
        md_obj, context_obj = {}, {}

        context_obj['Id'] = md_obj['id'] = demisto.get(element, 'id')
        context_obj['Key'] = md_obj['key'] = demisto.get(element, 'key')
        context_obj['Summary'] = md_obj['summary'] = demisto.get(element, 'fields.summary')
        context_obj['Status'] = md_obj['status'] = demisto.get(element, 'fields.status.name')

        assignee = demisto.get(element, 'fields.assignee')
        context_obj['Assignee'] = md_obj['assignee'] = "{name}({email})".format(
            name=assignee.get('displayName', 'null'),
            email=assignee.get('emailAddress', 'null')
        ) if assignee else 'null(null)'

        creator = demisto.get(element, 'fields.creator')
        context_obj['Creator'] = md_obj['creator'] = "{name}({email})".format(
            name=creator.get('displayName', 'null'),
            email=creator.get('emailAddress', 'null')
        ) if creator else 'null(null)'

        reporter = demisto.get(element, 'fields.reporter')
        md_obj['reporter'] = "{name}({email})".format(
            name=reporter.get('displayName', 'null'),
            email=reporter.get('emailAddress', 'null')
        ) if reporter else 'null(null)'

        md_obj.update({
            'issueType': demisto.get(element, 'fields.issuetype.description'),
            'priority': demisto.get(element, 'fields.priority.name'),
            'project': demisto.get(element, 'fields.project.name'),
            'labels': demisto.get(element, 'fields.labels'),
            'description': demisto.get(element, 'fields.description'),
            'duedate': demisto.get(element, 'fields.duedate'),
            'ticket_link': demisto.get(element, 'self'),
            'created': demisto.get(element, 'fields.created'),
        })
        attachments = demisto.get(element, 'fields.attachment')
        if isinstance(attachments, list):
            md_obj['attachment'] = ','.join(attach.get('filename') for attach in attachments)
            context_obj['attachment'] = ','.join(attach.get('filename') for attach in attachments)

        get_issue_obj['md'].append(md_obj)
        get_issue_obj['context'].append(context_obj)

    return get_issue_obj


def generate_md_context_create_issue(data, project_name=None, project_key=None):
    create_issue_obj = {"md": [], "context": {"Ticket": []}}  # type: ignore
    if project_name:
        data["projectName"] = project_name

    if project_key:
        data["projectKey"] = project_key

    elif demisto.getParam('projectKey'):
        data["projectKey"] = demisto.getParam('projectKey')

    create_issue_obj['md'].append(data)  # type: ignore
    create_issue_obj['context']['Ticket'].append(  # type: ignore
        {"Id": demisto.get(data, 'id'), "Key": demisto.get(data, 'key')})  # type: ignore
    return create_issue_obj


def generate_md_upload_issue(data, issue_id):
    upload_md = []
    if not isinstance(data, list):
        data = [data]

    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'issueId': issue_id,
            'attachment_name': demisto.get(element, 'filename'),
            'attachment_link': demisto.get(element, 'self')
        }
        upload_md.append(md_obj)

    return upload_md


def expand_urls(client, data, depth=0):
    if isinstance(data, dict) and depth < 10:
        for key, value in data.items():
            if key in ['_links', 'watchers', 'sla', 'request participants']:
                # dictionary of links
                if isinstance(value, dict):
                    for link_key, link_url in value.items():
                        value[link_key + '_expended'] = json.dumps(client.expand_url(link_url))
                # link
                else:
                    data[key + '_expended'] = json.dumps(client.expand_url(value))
            # search deeper
            else:
                if isinstance(value, dict):
                    return expand_urls(client, value, depth + 1)


def map_fields(data={}):
    fields = {
        "summary": "fields.summary",
        "projectKey": "fields.project.key",
        "issueTypeName": "fields.issuetype.name",
        "issueTypeId": "fields.issuetype.id",
        "projectName": "fields.project.name",
        "description": "fields.description",
        "labels": "fields.labels",
        "priority": "fields.priority.name",
        "dueDate": "fields.duedate",
        "assignee": "fields.assignee.name",
        "reporter": "fields.report.name",
        "parentIssueKey": "fields.parent.key",
        "parentIssueId": "fields.parent.id"
    }
    return_dict: dict = dict()
    data = {k: v for k, v in data.items() if k in fields}
    for k, v in data.items():
        mapped = fields[k].split(".")
        max_map = len(mapped) - 1
        current = return_dict
        for field in mapped:
            if field not in current:
                if mapped.index(field) == max_map:
                    current[field] = v
                else:
                    current[field] = dict()
            current = current[field]
    return return_dict


''' COMMAND FUNCTIONS '''


def test_module(client, params):
    """
    Performs basic get request to get item samples
    """
    user_data = client._http_request('GET', '/rest/api/latest/myself', auth=client.auth, resp_type='json')
    if params.get('isFetch'):
        client.run_query(params.get('query'), 0, max_results=1)

    if not user_data.get('active'):
        return_error(f'Test module for Jira failed for the configured parameters.'
                     f'please Validate that the user is active. Response: {str(user_data)}')

    demisto.results('ok')


def fetch_incidents(client):
    params = demisto.params()
    id_offset = None
    timestamp = None
    last_run = demisto.getLastRun()
    demisto.debug(f"last_run: {last_run}" if last_run else 'last_run is empty')
    if last_run:
        if last_run.get("idOffset"):
            id_offset = last_run.get("idOffset")
        if last_run.get("timestamp"):
            timestamp = last_run.get("timestamp")
            timestamp = dateparser.parse(timestamp).strftime("%Y-%m-%d %H:%M")
    timestamp = params.get('dateOffset', '2000-01-01') if not timestamp else timestamp
    id_offset = 0 if not id_offset else id_offset
    incidents, max_results = [], 50
    client.query = f'{client.query} AND createdDate > "{timestamp}" ORDER BY created ASC'

    res = client.fetch_incidents(client.query, '', max_results)
    if res:
        tickets = [x for x in res.get('issues', []) if int(x['id']) > int(id_offset)]
        curr_id = id_offset
        for ticket in tickets:
            ticket_id = int(ticket.get("id"))
            ticket_date = dateparser.parse(ticket.get('fields', {}).get('created'))
            timestampdate = dateparser.parse(
                timestamp,
                settings={
                    'TIMEZONE': '+0000',
                    'RETURN_AS_TIMEZONE_AWARE': True
                })
            if ticket_id == curr_id:
                continue
            id_offset = max(int(id_offset), ticket_id)

            timestamp = ticket.get('fields', {}).get('created') if ticket_date > timestampdate else timestamp
            ticket['dbotMirrorDirection'] = client.mirror_direction
            ticket['dbotMirrorInstance'] = client.instance_name
            ticket['dbotMirrorTags'] = [client.tag_internal, client.tag_public]
            new_incident = {k: v for k, v in ticket.items() if k != "fields"}
            for k, v in ticket['fields'].items():
                new_incident[k] = v
            incidents.append({
                "name": f"Jira - {new_incident.get('id')}",
                "details": '',
                "rawJSON": json.dumps(new_incident)
            })

    demisto.setLastRun({"idOffset": id_offset, "timestamp": timestamp})
    demisto.incidents(incidents)


def get_mapping_fields_command(client, args):
    new_schema = ISSUE_SCHEMA
    new_schema['dbotMirrorDirection'] = client.mirror_direction
    new_schema['dbotMirrorInstance'] = client.instance_name
    new_schema['dbotMirrorTags'] = [client.tag_internal, client.tag_public]
    schema = {
        "Issue Schema": ISSUE_SCHEMA
    }
    demisto.results(schema)


def get_remote_data_command(client, args):
    issue_id = args.get('id')
    last_update = args.get('lastUpdate')
    last_update_epoch = int(round((dateparser.parse(last_update).timestamp() * 1000), 0)) - 86400000  # Last 24 hours
    j_res = client.get_issue(issue_id)
    if not j_res:
        return issue_id
    new_incident = {k: v for k, v in j_res.items() if k != "fields"}
    for k, v in j_res['fields'].items():
        new_incident[k] = v
    entries = list()

    issue_comments = client.get_comments(
        issue_id,
        params={
            "orderBy": "-created",
            "maxResults": 500
        }
    )
    comments = [{
        "type": "Public note" if x['jsdPublic'] else "Internal note",
        "body": x['body'],
        "date": x['updated'],
        "email": x['updateAuthor']['emailAddress'],
        "name": x['updateAuthor']['displayName']
    } for x in issue_comments.get('comments', []) if dateparser.parse(x['updated']) > dateparser.parse(last_update)]
    entries += comments

    issue_attachments = demisto.get(j_res, 'fields.attachment')
    attachments = [{
        "type": "file",
        "date": x['created'],
        "attachment_url": x['content'],
        "filename": x['filename']
    } for x in issue_attachments if dateparser.parse(x['created']) > dateparser.parse(last_update)]
    entries += attachments

    issue_work_logs = client.get_worklog(
        issue_id,
        params={
            "startedAfter": last_update_epoch,
            "maxResults": 500
        }
    )
    work_logs = [{
        "type": "Work log",
        "body": x['comment'],
        "date": x['updated'],
        "email": x['updateAuthor']['emailAddress'],
        "name": x['updateAuthor']['displayName']
    } for x in issue_work_logs.get('worklogs', []) if dateparser.parse(x['updated']) > dateparser.parse(last_update)]
    entries += work_logs

    entries = sorted(entries, key=lambda x: x['date'])
    return_entries = list()
    for entry in entries:
        if entry['type'] != "file":
            author_string = f"{entry['name']} ({entry['email']})"
            return_entries.append({
                'Type': entryTypes['note'],
                'Category': 'chat',
                'Contents': f'### Jira comment from {author_string} ({entry["type"]}):\n\n{entry["body"]}',
                'ContentsFormat': formats['markdown']
            })
        else:
            return_entries.append(
                fileResult(
                    filename=entry['filename'],
                    data=client.get_download(entry['attachment_url'])
                )
            )
    demisto.results([new_incident] + return_entries)


def update_remote_system_command(client, args):
    data = args.get('data', {})
    delta = args.get('delta', {})
    changes = {k: v for k, v in delta.items() if k in data.keys()}
    entries = args.get('entries', [])
    incident_changed = args.get('incidentChanged')
    issue_id = args.get('remoteId')
    if entries and len(entries) > 0:
        for entry in entries:
            entry['user'] = 'Cortex XSOAR' if not entry['user'] else entry['user']
            if entry.get("fileID", None):
                client.upload_file(entry['id'], issue_id)
            comment = f"({entry['user']}): {entry['contents']}"
            tags = entry['tags']

            if client.tag_public in tags:
                client.add_comment(issue_id, comment, None, False)
            elif client.tag_internal in tags:
                client.add_comment(issue_id, comment, None, True)

    if incident_changed:
        client.edit_issue(issue_id, issue={"fields": changes})
    demisto.results(issue_id)


def issue_query_command(client, args):
    query = args.get('query')
    max_results = args.get('maxResults')
    start_at = args.get('startAt', 0)
    headers = args.get('headers', '')
    j_res = client.run_query(
        query=query,
        max_results=max_results,
        start_at=start_at
    )
    if not j_res:
        outputs = contents = {}
        human_readable = 'No issues matched the query.'
    else:
        issues = j_res.get('issues', {})
        md_and_context = generate_md_context_get_issue(issues)
        human_readable = tableToMarkdown(demisto.command(), t=md_and_context['md'], headers=argToList(headers))
        contents = j_res
        outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}

    return_outputs(human_readable, outputs, contents)


def get_issue_command(client, args, headers=None, is_update=False):
    issue_id = args.get('issueId')
    headers = headers if headers else args.get('headers', None)
    expand_links = True if args.get('expandLinks', 'false') == 'true' else False
    get_attachments = True if args.get('getAttachments', 'false') == 'true' else False

    j_res = client.get_issue(issue_id)
    if expand_links:
        expand_urls(client, j_res)

    attachments = demisto.get(j_res, 'fields.attachment')  # list of all attachments

    if get_attachments and attachments:
        for attachment in attachments:
            link = attachment['content']
            filename = attachment['filename']
            demisto.results(fileResult(filename=filename, data=client.get_download(link)))

    md_and_context = generate_md_context_get_issue(j_res)
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], argToList(headers))
    if is_update:
        human_readable += f'Issue #{issue_id} was updated successfully'

    contents = j_res
    outputs = {'Ticket(val.Id == obj.Id)': md_and_context['context']}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


def create_issue_command(client, args):
    if "issueJson" in args:
        j_res = client._http_request('POST', '/rest/api/latest/issue',
                                     json.dumps(args['issueJson']), auth=client.auth, resp_type='json')
    else:
        issue = map_fields(data=args)
        j_res = client._http_request('POST', '/rest/api/latest/issue', data=json.dumps(issue), auth=client.auth, resp_type='json')

    md_and_context = generate_md_context_create_issue(j_res, project_key=demisto.getArg('projectKey'),
                                                      project_name=demisto.getArg('issueTypeName'))
    human_readable = tableToMarkdown(demisto.command(), md_and_context['md'], "")
    contents = j_res
    outputs = md_and_context['context']
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)


def issue_upload_command(client, args):
    issue_id = args.get('issueId')
    entry_ID = args.get('upload', None)
    attachment_name = args.get('attachmentName', None)
    if not entry_ID:
        return_error('You must specify an entryID to upload')
    j_res = client.upload_file(entry_ID, issue_id, attachment_name)
    md = generate_md_upload_issue(j_res, issue_id)
    human_readable = tableToMarkdown(demisto.command(), md, "")
    contents = j_res
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


def add_comment_command(client, args):
    issue_id = args.get('issueId')
    comment = args.get('comment')
    visibility = args.get('visibility', '')
    internal = True if args.get('internal', 'false') == 'true' else False

    data = client.add_comment(issue_id, comment, visibility, internal)
    md_list = []
    if not isinstance(data, list):
        data = [data]
    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'key': demisto.get(element, 'updateAuthor.key'),
            'comment': demisto.get(element, 'body'),
            'ticket_link': demisto.get(element, 'self')
        }
        md_list.append(md_obj)

    human_readable = tableToMarkdown(demisto.command(), md_list, "")
    contents = data
    return_outputs(readable_output=human_readable, outputs={}, raw_response=contents)


def add_link_command(client, args):
    issue_id = args.get('issueId')
    title = args.get('title')
    url = args.get('url')
    summary = args.get('summary', None)
    global_id = args.get('globalId', None)
    relationship = args.get('relationship', None)
    application_type = args.get('applicationType', None)
    application_name = args.get('applicationName', None)

    data = client.add_link(
        issue_id=issue_id,
        title=title,
        url=url,
        summary=summary,
        global_id=global_id,
        relationship=relationship,
        application_type=application_type,
        application_name=application_name
    )
    md_list = []
    if not isinstance(data, list):
        data = [data]
    for element in data:
        md_obj = {
            'id': demisto.get(element, 'id'),
            'key': demisto.get(element, 'updateAuthor.key'),
            'comment': demisto.get(element, 'body'),
            'ticket_link': demisto.get(element, 'self')
        }
        md_list.append(md_obj)
    human_readable = tableToMarkdown(demisto.command(), md_list, "", removeNull=True)
    return_outputs(readable_output=human_readable, outputs={}, raw_response=data)


def edit_issue_command(client, args, headers=None, status=None, **_):
    issue_id = args.get('issueId')
    status = args.get('status', None)
    issue = map_fields(data=args)
    client.edit_issue(issue_id, issue)
    if status:
        client.edit_status(issue_id, status)
    return get_issue_command(client, args, is_update=True)


def get_comments_command(client, args):
    issue_id = args.get('issueId')
    body = client.get_comments(issue_id)
    comments = []
    if body.get("comments"):
        for comment in body.get("comments"):
            comments.append({
                'Comment': comment.get("body"),
                'User': demisto.get(comment, 'updateAuthor.name'),
                'Created': comment.get("created")
            })

        human_readable = tableToMarkdown("Comments", comments)
        contents = body
        outputs = {'Ticket(val.Id == obj.Id)': {'Id': issue_id, "Comment": comments}}
        return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)

    else:
        demisto.results('No comments were found in the ticket')


def delete_issue_command(client, args):
    issue_id = args.get('issueIdOrKey')
    res = client.delete_issue(issue_id)
    if res.status_code == 204:
        demisto.results('Issue deleted successfully.')
    else:
        demisto.results('Failed to delete issue.')


def get_id_offset_command(client, args):
    query = "ORDER BY created ASC"
    j_res = client.run_query(query=query, max_results=1)
    first_issue_id = j_res.get('issues', [{}])[0].get('id')
    return_outputs(
        readable_output=f"ID Offset: {first_issue_id}",
        outputs={'Ticket.idOffSet': first_issue_id},
    )


def main():
    params = demisto.params()
    base_url = params.get('url').rstrip('/') + '/'
    mirroring = None if params.get('mirror', 'Disabled') == 'Disabled' else params.get('mirror')
    tag_internal = params.get('tag_internal_note')
    tag_public = params.get('tag_public_note')
    username = params.get('username', None)
    password = params.get('password', None)
    api_token = params.get('APItoken', None)
    consumer_key = params.get('consumerKey', None)
    access_token = params.get('accessToken', None)
    private_key = params.get('privateKey', None)
    query = params.get('query', '')
    id_offset = params.get('idOffset', None)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {'Content-Type': 'application/json'}

    args = demisto.args()

    command = demisto.command()
    commands = {
        'jira-issue-query': issue_query_command,
        'jira-get-issue': get_issue_command,
        'jira-create-issue': create_issue_command,
        'jira-issue-upload-file': issue_upload_command,
        'jira-issue-add-comment': add_comment_command,
        'jira-issue-add-link': add_link_command,
        'jira-edit-issue': edit_issue_command,
        'jira-get-comments': get_comments_command,
        'jira-delete-issue': delete_issue_command,
        'jira-get-id-offset': get_id_offset_command
    }

    # try:

    demisto.debug(f'Command being called is {command}')

    client = Client(
        base_url=base_url,
        mirroring=mirroring,
        tag_internal=tag_internal,
        tag_public=tag_public,
        username=username,
        password=password,
        api_token=api_token,
        consumer_key=consumer_key,
        access_token=access_token,
        private_key=private_key,
        query=query,
        id_offset=id_offset,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers
    )

    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module(client, params)

    elif demisto.command() == 'fetch-incidents':
        # Set and define the fetch incidents command to run after activated via integration settings.
        fetch_incidents(client)

    elif demisto.command() == 'get-mapping-fields':
        get_mapping_fields_command(client, args)

    elif demisto.command() == 'get-remote-data':
        get_remote_data_command(client, args)

    elif demisto.command() == 'update-remote-system':
        update_remote_system_command(client, args)

    elif command in commands:
        commands[command](client, args)

    # except Exception as err:
    #    return_error(str(err))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
