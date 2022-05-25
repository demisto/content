import pytest
from GitLabEventCollector import GetEvents, Client
from SiemApiModule import *  # noqa # pylint: disable=unused-wildcard-import

events = [{'created_at': '2022-04-17T12:31:36.667', 'entity_type': 'Group', 'id': '1'},
          {'created_at': '2022-05-17T12:31:36.667', 'entity_type': 'Group', 'id': '2'},
          {'created_at': '2022-06-17T12:31:36.667', 'entity_type': 'Group', 'id': '3'},
          {'created_at': '2022-04-17T12:31:36.667', 'entity_type': 'Project', 'id': '1'},
          {'created_at': '2022-05-17T12:31:36.667', 'entity_type': 'Project', 'id': '2'},
          {'created_at': '2022-06-17T12:31:36.667', 'entity_type': 'Project', 'id': '3'}
          ]
options = IntegrationOptions.parse_obj({
    'api_key': {'credentials': {'password': 'XXXXXX'}},
    'after': '3 Days',
    'url': 'https:/XXX.XXX.run',
    'project_ids': 'XXX',
    'group_ids': 'XXX',
    'audit_events_type': 'groups, projects',
    'push_events': 'true',
    'product': 'gitlab',
    'vendor': 'gitlab',
})
request_object = {
    'method': Method.GET,
    'url': 'https://test.test',
    'headers': {},
}
request = IntegrationHTTPRequest(**request_object)
client = Client(request, options, '2022-05-22T16:25:59.776885')
get_events = GetEvents(client, options)


def test_get_last_run():
    assert GetEvents.get_last_run(events) == {'groups': '2022-06-17T12:31:36.667',
                                              'projects': '2022-06-17T12:31:36.667'}


def test_prepare_request():
    client.prepare_request()
    assert client.request.url == 'https://test.test?created_after=2022-05-22T16:25:59.776885&per_page=100&page=1'
