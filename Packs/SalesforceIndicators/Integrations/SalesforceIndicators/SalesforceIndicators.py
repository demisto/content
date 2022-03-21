import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

from datetime import datetime

import dateparser
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' HELPER FUNCTIONS '''


class Client(BaseClient):
    def __init__(self, base_url, username, password, client_id, client_secret, object_name, key_field, query_filter,
                 fields, history, verify, proxy, feedReputation, ok_codes=[], headers=None, auth=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)
        self.username = username
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.session_data = self.get_new_token()
        if not self.session_data or not self.session_data['access_token']:
            return_error("Failed to get access token for Salesforce integration")
        self._headers = {
            "Authorization": f"Bearer {self.session_data['access_token']}",
            "Content-Type": "application/json"
        }
        self._base_url = urljoin(self._base_url, '/services/data/v39.0/')
        self.object_name = object_name
        self.key_field = key_field
        self.query_filter = query_filter
        self.fields = fields
        self.history = history
        self.feedReputation = feedReputation
        self.score = 1 if self.feedReputation == 'Good'\
            else 2 if self.feedReputation == 'Suspicious'\
            else 3 if self.feedReputation == 'Bad'\
            else 0

    def get_new_token(self):
        body = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password
        }
        res = self._http_request(
            'POST',
            '/services/oauth2/token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data=body
        )
        return res

    def query_object(self, fields, table, condition=None):
        if condition:
            query = f"SELECT {','.join(fields)} FROM {table} WHERE {condition}"
        else:
            query = f"SELECT {','.join(fields)} FROM {table}"
        return self.raw_query(query)

    def raw_query(self, query, raw_query=False):

        params = {
            "q": query
        }

        if raw_query:
            res = self._http_request(
                'GET',
                f'{query}'
            )
        else:
            res = self._http_request(
                'GET',
                'query',
                params=params
            )
        return res

    def get_object_description(self):
        res = self._http_request('GET', f'sobjects/{self.object_name}/describe/')
        return res


def fetch_indicators_command(client, params, manual_run=False):

    indicators_unparsed = list()
    indicators = list()
    now = datetime.utcnow()
    date_filter = dateparser.parse(f"{client.history} days ago", settings={
                                   'RELATIVE_BASE': now}).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    integration_context = get_integration_context()
    if integration_context:
        last_run = integration_context.get('lastRun')
    else:
        last_run = None
    object_fields = None
    if client.fields:
        object_fields = client.fields.split(",")
    else:
        object_fields = sorted([x['name'] for x in client.get_object_description()['fields']])
    if "id" not in object_fields and "Id" not in object_fields:
        object_fields.append("id")

    if client.query_filter:
        search_criteria = f"{client.query_filter}"
        if last_run:
            search_criteria = f"{search_criteria} AND LastModifiedDate >= {last_run}"
    else:
        if last_run:
            search_criteria = f"LastModifiedDate >= {last_run}"
        else:
            search_criteria = f"LastModifiedDate > {date_filter}"
    indicators_raw = client.query_object(object_fields, client.object_name, search_criteria)
    if indicators_raw.get('totalSize', 0) > 0:
        for indicator in indicators_raw.get('records', []):
            indicators_unparsed.append({k: v for k, v in indicator.items() if k != 'attributes'})
        more_records = True if indicators_raw.get('nextRecordsUrl', None) else False

        while more_records:
            next_records = "/".join(indicators_raw.get('nextRecordsUrl').split("/")[-2:])
            indicators_raw = client.raw_query(next_records, raw_query=True)
            for indicator in indicators_raw.get('records', []):
                indicators_unparsed.append({k: v for k, v in indicator.items() if k != 'attributes'})

            more_records = True if indicators_raw.get('nextRecordsUrl', None) else False

    for item in indicators_unparsed:
        try:
            value = item[client.key_field] if client.key_field in item else None
            if value:
                item['object_name'] = client.object_name
                indicator = {
                    "value": value,
                    "type": client.object_name,
                    "rawJSON": item,
                    "score": client.score
                }
                indicators.append(indicator)
        except Exception:
            pass

    if not manual_run:

        # Update the last run time
        last_run = now.strftime("%Y-%m-%dT%H:%M:00Z")
        set_integration_context({"lastRun": last_run})

        # We submit indicators in batches
        for b in batch(indicators, batch_size=2000):
            demisto.createIndicators(b)

    else:
        demisto.results({
            "SFDC.Indicators": indicators,
            "Count": len(indicators)
        })


def test_module(client):
    demisto.results('ok')


def main():
    params = demisto.params()
    proxies = handle_proxy()
    verify_certificate = not params.get('insecure', False)
    url = params.get('InstanceURL')
    credentials = params.get('credentials')
    username = credentials.get('identifier')
    password = credentials.get('password')
    client_id = params.get('clientID')
    client_secret = params.get('clientSecret')
    object_name = params.get('object')
    key_field = params.get('key_field')
    query_filter = params.get('filter', None)
    fields = params.get('fields', None)
    history = params.get('indicator_history', 365)
    reputation = params.get('feedReputation', 'None')

    command = demisto.command()

    client = Client(url, username, password, client_id, client_secret, object_name, key_field,
                    query_filter, fields, history, verify_certificate, proxies, reputation)

    if command == 'test-module':
        test_module(client)

    elif command == 'fetch-indicators':
        fetch_indicators_command(client, params)

    elif command == 'salesforce-get-indicators':
        fetch_indicators_command(client, params, manual_run=True)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
