import os
import requests
import traceback
import json
from datetime import datetime, timedelta
from requests import HTTPError
from CommonServerPython import *
import demistomock as demisto

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
EMAIL = demisto.params().get('credentials')['identifier']
API_KEY = demisto.params().get('credentials')['password']
FIRST_RUN_TIME_RANGE = int(demisto.params().get('first_run_time_range').strip())
PROXY = demisto.params().get('proxy')
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


class Portal():
    def __init__(self, bearer=None, portal_url="https://services.fieldeffect.net/v1", provider=None, verbose=False):
        self.auth = None
        self.portal_url = portal_url
        self.verbose = verbose
        self.provider_name = provider
        if bearer == "gan ceann":
            self.scheme = self.AuthScheme.FES
            # Headless login for those cursed with a GUI
        elif bearer:
            self.scheme = self.AuthScheme.BEARER
            self.auth = {"token": bearer, "expires": datetime.now() + timedelta(days=10 * 365), "refresh": None}
            self.provider_id = self.get_provider_id()
        else:
            raise ValueError('Bearer is missing')

    class AuthScheme(object):
        FES = 'FieldEffectAuth'
        BEARER = 'Bearer'
        KEY = 'FieldEffectKey'

    def try_saved_token(self, token):
        # Return True if this token works, also save this token as the token
        # Return False if this token doesn't work and user will need to auth
        try:
            self.auth = token
            if self.provider_name:
                self.provider_id = self.find_provider(self.provider_name)
            else:
                self.provider_id = self.get_provider_id()
            return True

        except requests.exceptions.HTTPError:
            self.auth = None
            return False

    def get(self, uri, query=None, headers=None, remove_subdomain=False, **kwargs):
        return self._request(uri, method='GET', query=query, headers=headers, remove_subdomain=remove_subdomain, **kwargs)

    def _request(self, uri, method='GET', query=None, json=None, data=None, files=None, headers=None,
                 remove_subdomain=False, **kwargs):
        all_headers = {
            'Content-Type': 'application/json'
        } if json is not None else {}

        if headers is not None:
            all_headers.update(headers)
        if self.auth:
            auth = '{} {}'.format(self.scheme, self.auth['token'])
            all_headers.update({'Authorization': auth})

        url = '{}/{}'.format(self.portal_url, uri if len(kwargs) == 0 else uri.format(**kwargs))
        if remove_subdomain:
            url = url.replace('services.', '')

        if self.verbose:
            sys.stdout.write('{} {} '.format(method, url))

        if method == 'GET':
            r = requests.get(url, headers=all_headers, params=query)
        elif method == 'POST':
            r = requests.post(url, headers=all_headers, json=json, data=data, params=query, files=files)
        elif method == 'PUT':
            r = requests.put(url, headers=all_headers, json=json, data=data, params=query, files=files)
        elif method == 'DELETE':
            r = requests.delete(url, headers=all_headers, params=query)
        else:
            raise AssertionError('Unsupported HTTP method: {}'.format(method))

        if self.verbose:
            sys.stdout.write(str(r.status_code) + '\n')
        if r.status_code >= 400:
            raise HTTPError(r.text)
        return r

    def get_provider_id(self):
        r = self.get('my_providers', auth=self.auth)
        if not r.json():
            raise ValueError(f'Account {EMAIL} is not part of any provider')
        return r.json()[0]['ID']

    def find_provider(self, provider):
        r = self.get('providers', auth=self.auth)
        providers = r.json()
        for prov in providers:
            if provider == prov["name"] or provider == prov["ID"]:
                return prov["ID"]
        return None

    def get_organizations(self):
        r = self.get('my_providers/{id}/organizations', auth=self.auth, id=self.provider_id)
        return r.json()

    def find_organizations(self, org):
        r = self.get('my_providers/{id}/organizations', auth=self.auth, id=self.provider_id)
        orgs = r.json()
        matches = []
        for o in orgs:
            if org.lower() in o["name"].lower():
                matches.append(o)
        return matches

    def get_aros(self, **kwargs):
        aros = []
        if "query" not in kwargs:
            kwargs["query"] = {}
        kwargs["query"]["limit"] = 500
        r = self.get('providers/{id}/aros', auth=self.auth, id=self.provider_id, **kwargs).json()
        aros.extend(r["items"])
        while len(aros) < r["total"]:
            kwargs["query"]["page"] = r["page"] + 1
            r = self.get('providers/{id}/aros', auth=self.auth, id=self.provider_id, **kwargs).json()
            aros.extend(r["items"])
        return aros

    def get_active_response_profile(self, org_id):
        r = self.get('my_organizations/{org_id}', auth=self.auth, org_id=org_id)
        org_details = r.json()
        return org_details.get('active_response_profile', None)


''' Commands '''


def portal_check():
    '''
    Poking to the portal to make sure it's up
    '''
    try:
        Portal(bearer=API_KEY)
        return True
    except Exception:
        demisto.log(traceback.format_exc())
        return False


def fetch_incidents(last_run, first_run_time_range):
    last_fetch = last_run.get('last_fetch', None)
    last_aro_id = last_run.get('last_aro_id', None)
    aro_time_max = datetime.utcnow()

    if last_fetch is None:
        aro_time_min = aro_time_max - timedelta(days=first_run_time_range)
    else:
        aro_time_min = dateparser.parse(last_fetch)

    p = Portal(bearer=API_KEY)
    query = {'resolution': 'Unresolved',
             'since': aro_time_min.strftime(DATE_FORMAT),
             'until': aro_time_max.strftime(DATE_FORMAT)}
    aros = p.get_aros(query=query)

    incidents = []

    latest_created_time = aro_time_min
    # aros is ordered by most recent ARO
    # it's required to traverse aros in chronological order (so last element first)
    # to avoid duplicating incidents
    for a in reversed(aros):
        if a['ID'] != last_aro_id:
            created_time = dateparser.parse(a['creation_time'])
            created_time_str = created_time.strftime(DATE_FORMAT)

            if a.get('organization', None):
                org_name = a['organization'].get('name', 'No org name')
                org_id = a['organization'].get('ID', None)
            else:
                org_name = 'No org name'
                org_id = None

            aro_type = a.get('type', 'No ARO type')

            aro_title = a.get('title', 'No title')

            incident = {
                'name': f'''[{org_name}] [{aro_type}] {aro_title}''',
                'occured': created_time_str,
                'rawJSON': json.dumps(a)
            }
            if a.get('severity', None):
                # XSOAR mapping
                # Unknown: 0
                # Informational: 0.5
                # Low: 1
                # Medium: 2
                # High: 3
                # Critical: 4
                severity_from_portal = a['severity']
                if severity_from_portal == 'Informational':
                    incident['severity'] = 0.5
                elif severity_from_portal == 'Warning':
                    incident['severity'] = 1
                elif severity_from_portal == 'Low':
                    incident['severity'] = 1
                elif severity_from_portal == 'Medium':
                    incident['severity'] = 2
                elif severity_from_portal == 'High':
                    incident['severity'] = 3
                elif severity_from_portal == 'Critical':
                    incident['severity'] = 4
            else:
                incident['severity'] = 0
            if a.get('details', None):
                incident['details'] = a['details']
                if a.get('steps', None):
                    if len(a['steps']) > 0:
                        incident['details'] += '\n\nMitigation Steps\n'
                        for step in a['steps']:
                            incident['details'] += f'''- {step['label']}\n'''
                if org_id:
                    active_response_profile = p.get_active_response_profile(org_id)
                    if active_response_profile:
                        policy = active_response_profile.get('response_policy')
                        options = active_response_profile.get('options')
                        incident['details'] += '\nActive Response Profile\n'
                        incident['details'] += f'''- Response policy: {policy}\n'''
                        incident['details'] += f'''- Exclusions/ Modifications: {options}\n'''

            incidents.append(incident)

            if created_time > latest_created_time:
                latest_created_time = created_time
                last_aro_id = a['ID']

    next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT),
                'last_aro_id': last_aro_id}

    return next_run, incidents


def get_aros():
    p = Portal(bearer=API_KEY)

    q = demisto.args().get('query', None)

    if q:
        query = {}  # pragma: no cover
        for param in q.split('&'):
            key = param.split('=')[0]
            value = param.split('=')[1]
            query[key] = value

            if 'org' in query:
                org = p.find_organizations(query['org'])
                if not org:
                    raise ValueError(f'Unknown organization named {query["org"]}')
                del query['org']
                query['organization_id'] = org[0]['ID']
        aros = p.get_aros(query=query)
    else:
        aros = p.get_aros()

    details = argToBoolean(demisto.args().get('details', 'false'))
    keys = ['title',
            'organization',
            'resolution',
            'severity',
            'status',
            'type']

    if not details:
        filtered_r = []
        # returning only data in keys
        for aro in aros:
            a = {k: aro[k] for k in keys}
            filtered_r.append(a)
        return filtered_r
    else:
        return aros


def list_organizations():
    p = Portal(bearer=API_KEY)

    return p.get_organizations()


def main():
    demisto.info(f'{demisto.command()} is called')
    try:
        if demisto.command() == 'test-module':
            if portal_check():
                return_results('ok')
            else:
                return_results('nok')

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                last_run=demisto.getLastRun(),
                first_run_time_range=FIRST_RUN_TIME_RANGE)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'cov-mgsec-get-aro':
            r = get_aros()
            if r:
                readable_output = tableToMarkdown('AROs', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No AROs found'

            results = CommandResults(
                outputs_prefix='FESPortal.ARO',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        elif demisto.command() == 'cov-mgsec-list-org':
            r = list_organizations()
            if r:
                readable_output = tableToMarkdown('Organizations', r, removeNull=True, headerTransform=string_to_table_header)
            else:
                readable_output = 'No organizations found'

            results = CommandResults(
                outputs_prefix='FESPortal.Org',
                outputs_key_field='ID',
                outputs=r,
                readable_output=readable_output
            )
            return_results(results)
        else:
            msg = f'Unknown command {demisto.command()}'
            demisto.error(msg)
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}. {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
