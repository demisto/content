import pytest
from Database import Client

"""
Response from API mock.
[
    [ID, DATE, NAME, URGENCY]
]
"""
response_mock = [
    [1, "2010-01-01T00:00:00Z", 'Guy Freund', 'HIGH'],
    [2, "2011-01-01T00:00:00Z", 'Guy Freund', 'MED'],
    [3, "2012-01-01T00:00:00Z", 'Guy Freund', 'LOW']
]
context_output = {'Database': {'Result': [
    {'ID': 1, 'Timestamp': '2010-01-01T00:00:00Z', 'Name': 'Guy Freund', 'Urgency': 'HIGH'},
    {'ID': 2, 'Timestamp': '2011-01-01T00:00:00Z', 'Name': 'Guy Freund', 'Urgency': 'MED'},
    {'ID': 3, 'Timestamp': '2012-01-01T00:00:00Z', 'Name': 'Guy Freund', 'Urgency': 'LOW'}]}}

test_inputs_query = [
    (response_mock, "Guy Freund", context_output),
    ([], "Found no results for given query.", {})

]

test_inputs_fetch_incidents = [
    (
        response_mock, {'last_run': '2010-01-01T00:00:00Z'}, '3 days', 'incidents', '*', 'DATE', 3,
        '2012-01-01T00:00:00Z'),
    ([], {'last_run': '2010-01-01T00:00:00Z'}, '3 days', 'incidents', '*', 'DATE', 0, '2010-01-01T00:00:00Z')
]


class TestDatabase:
    url = "http://123-fake-api.com"
    client = Client(url)

    @pytest.mark.parametrize('req_input,expected_md,expected_context', test_inputs_query)
    def test_query(self, requests_mock, req_input, expected_md, expected_context):
        from Database import query_command
        requests_mock.post(self.url, json=req_input)
        readable_output, context, _ = query_command(self.client,
                                                    {
                                                        "query": "qqq",
                                                        "columns": "ID,Timestamp,Name,Urgency"
                                                    })
        assert expected_md in readable_output
        assert expected_context == context

    @pytest.mark.parametrize('req_input,last_run,fetch_time,table_name,columns,date_name,incidents_len,new_last_run',
                             test_inputs_fetch_incidents)
    def test_fetch_incidents(self, requests_mock,
                             req_input, last_run, fetch_time, table_name, columns, date_name, incidents_len,
                             new_last_run
                             ):
        from Database import fetch_incidents_command
        requests_mock.post(self.url, json=req_input)
        last_fetch, incidents = fetch_incidents_command(self.client, last_run, '3 days', 'incidents', '*', 'occurred')
        assert last_fetch.get('last_run') == new_last_run
        assert len(incidents) == incidents_len
