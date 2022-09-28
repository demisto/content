from freezegun import freeze_time
import Packetsled


def test_number_to_ip():
    assert Packetsled.number_to_ip(168496141) == '10.11.12.13'


def test_ip_to_number():
    assert Packetsled.ip_to_number('10.11.12.13') == 168496141


def test_format_flow():
    flow = {
        'src_ip': 168496141,
        'dest_ip': 168496141,
        'family': [2, 4, 6]
    }
    assert Packetsled.format_flow(flow) == {'src_ip': '10.11.12.13', 'dest_ip': '10.11.12.13',
                                            'family': ['network_management', 'tunnel', 'application_service']}


@freeze_time("2022-09-08 17:22:13 UTC")
def test_getTime():
    time = Packetsled.getTime('2017-01-12T14:12:06.000Z')
    assert time == 1484230326.0


@freeze_time("2022-09-08 17:22:13 UTC")
def test_isoTime():
    time = Packetsled.getTime('2017-01-12T14:12:06.000Z')
    assert time == 1484230326.0


def test_coalesceToArray():
    assert Packetsled.coalesceToArray({'1': True, '2': False}) == [{'1': True, '2': False}]


@freeze_time("2022-09-08 17:22:13 UTC")
def test_make_timerange():
    dargs = {
        'stop_time': '2017-01-12T14:12:06.000Z',
        'start_time': '2016-01-12T14:12:06.000Z'
    }
    assert Packetsled.make_timerange(dargs) == (1452607926.0, 1484230326.0)


def test_make_query():
    dargs = {
        'stop_time': '2017-01-12T14:12:06.000Z',
        'start_time': '2016-01-12T14:12:06.000Z',
        'family': ['network_management', 'tunnel', 'application_service']
    }
    assert Packetsled.make_query(dargs) == {'time': {'=': {'scalars': [],
                                                           'ranges': [{'v1': 1452607926.0, 'v2': 1484230326.0}]}},
                                            'family': {
                                                '=': {'scalars': [{'v1': 2}, {'v1': 4}, {'v1': 6}], 'ranges': []}}}
