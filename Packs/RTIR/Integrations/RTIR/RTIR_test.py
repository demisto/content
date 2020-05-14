import requests
import demistomock as demisto


class DotDict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def test_query_formatting(mocker):
    args = {
        'ticket-id': 1111
    }
    params = {
        'server': 'test',
        'credentials': {
            'identifier': 'test',
            'password': 'test'
        },
        'fetch_priority': 1,
        'fetch_status': 'test',
        'fetch_queue': 'test',
        'proxy': True
    }

    mocker.patch.object(requests, 'session', return_value=DotDict({}))
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'params', return_value=params)

    from RTIR import build_search_query
    query = build_search_query()
    assert not (query.endswith('+OR+') or query.endswith('+AND+'))
