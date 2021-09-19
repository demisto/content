from freezegun import freeze_time
from datetime import datetime
import demistomock as demisto
import RsaNetWitnessPacketsAndLogsV2


# @freeze_time('Fri Nov 5 10:11:12 2021')
class TestGetTimeRange:
    @staticmethod
    def test_sanity():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('last4d', datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('last 4 days')
        assert start == start2
        assert end == end2

    @staticmethod
    def test_today():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('today', datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('Today')
        assert start == start2
        assert end == end2

    @staticmethod
    def test_yesterday():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('yesterday', datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('Yesterday')
        assert start == start2
        assert end == end2

    @staticmethod
    @freeze_time('Fri Nov 5 10:11:12 2021')
    def test_custom_times_only_start():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('2020-11-01 00:00:00 - 2021-11-05 10:11:12',
                                                                      datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('Custom', start_time='2020-11-01 00:00:00')
        assert end == end2
        assert start == start2

    @staticmethod
    @freeze_time('Fri Nov 5 10:11:12 2021')
    def test_custom_times_only_end():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('2020-11-01 00:00:00 - 2020-12-01 10:00:00',
                                                                      datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('Custom', end_time='2020-12-01 10:00:00')
        # assert start == start2
        assert end == end2

    @staticmethod
    @freeze_time('Fri Nov 5 10:11:12 2021')
    def test_custom_times_start_and_end():
        start, end = RsaNetWitnessPacketsAndLogsV2.utilParseTimeRange('2020-11-01 00:00:00 - 2020-12-01 10:00:00',
                                                                      datetime(2021, 11, 10).timestamp())
        start2, end2 = RsaNetWitnessPacketsAndLogsV2.get_time_range('Custom',
                                                                    start_time='2020-11-01 00:00:00',
                                                                    end_time='2020-12-01 10:00:00')
        assert start == start2
        assert end == end2


class TestNwQueryResponse:
    @staticmethod
    def test_parsing_sanity(mocker):
        query_response = RsaNetWitnessPacketsAndLogsV2.NwQueryResponse()
        raw_response = (
            '[id1=60  id2=120\n'
            'id1=0    id2=50   count=50  format=1  value=Session Packet Count  type=tcp.flags  flags=2147483665  group=100\n'
            'id1=50   id2=100  count=51  format=2  value=Session Streams   type=tcp.flags  flags=2147483665  group=101\n'
            'id1=100  id2=150  count=52  format=3  value=Session type  type=tcp.flags  flags=2147483665  group=102\n'
            ']'
        )

        query_response.parseFromHttpResponse(raw_response)
        assert query_response.id1 == 60
        assert query_response.id2 == 120
        assert len(query_response.result) == 3
        for i, field in enumerate(query_response.result):
            assert field.id1 == i * 50
            assert field.id2 == (i + 1) * 50
            assert field.count == i + 50
            assert field.format == i + 1
            assert field.value in ['Session Packet Count', 'Session Streams', 'Session type']
            assert field.type == 'tcp.flags'
            assert field.flags == 2147483665
            assert field.group == i + 100

    @staticmethod
    def test_missing_fields():
        query_response = RsaNetWitnessPacketsAndLogsV2.NwQueryResponse()
        raw_response = (
            '[id1=1  id2=3\n'
            'id1=1   id2=1   count=1  format=1                          type=packets  flags=2147483665  group=100\n'
            'id1=2   id2=2  count=2  format=2  value=Session Streams   type=packets  flags=2147483665  group=101\n'
            'id1=3   id2=3            format=3  value=type              type=packets  flags=2147483665  group=102\n'
            ']'
        )

        query_response.parseFromHttpResponse(raw_response)
        assert query_response.result[0].id1 == 1
        assert query_response.result[0].value is None

        assert query_response.result[1].id1 == 2
        assert query_response.result[1].group == 101

        assert query_response.result[2].id1 == 3
        assert query_response.result[2].count == 0


class TestEventInfoCommand:
    @staticmethod
    def test_sanity(mocker):
        # mocking command requests
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getTimeRange',
                            return_value=(datetime(1600, 11, 5).timestamp(), datetime(2020, 11, 5).timestamp()))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getSessionIdRange',
                            return_value=(1, 100))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getMetaIdRange',
                            return_value=(101, 1000))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getMetaInformation',
                            return_value={
                                'NoIndex': RsaNetWitnessPacketsAndLogsV2.NwMeta(
                                    'NoIndex',
                                    RsaNetWitnessPacketsAndLogsV2.NwMetaFormat.nwInt32,
                                ),
                                'KeyIndex': RsaNetWitnessPacketsAndLogsV2.NwMeta(
                                    'KeyIndex',
                                    RsaNetWitnessPacketsAndLogsV2.NwMetaFormat.nwInt32,
                                    flags=2,
                                ),
                                'ValueIndex': RsaNetWitnessPacketsAndLogsV2.NwMeta(
                                    'ValueIndex',
                                    RsaNetWitnessPacketsAndLogsV2.NwMetaFormat.nwInt32,
                                    flags=3,
                                ),
                            })
        results = RsaNetWitnessPacketsAndLogsV2.nw_events_info_command(
            RsaNetWitnessPacketsAndLogsV2.NwCoreClient('host', 443, 'user', 'password', False, True, True), {})

        assert len(results) == 3
        assert {'Range': 'Range of Session Ids', 'Start Range': 1, 'End Range': 100} in results[0].raw_response

        assert results[1].raw_response[2]['Range type'] == 'Meta Not Indexed'  # unindexed
        assert results[1].raw_response[2]['Count'] == 1  # unindexed

        assert results[2].raw_response['INDEX_NONE'] == ['NoIndex']
        assert results[2].raw_response['INDEX_KEY'] == ['KeyIndex']
        assert results[2].raw_response['INDEX_VALUE'] == ['ValueIndex']


class TestEventValuesCommand:
    @staticmethod
    def test_sanity(mocker):
        # mocking command requests
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getTimeRange',
                            return_value=(datetime(1600, 11, 5).timestamp(), datetime(2020, 11, 5).timestamp()))

        results = RsaNetWitnessPacketsAndLogsV2.nw_events_values_command(
            RsaNetWitnessPacketsAndLogsV2.NwCoreClient('host', 443, 'user', 'password', False, True, True), {})

        assert results.raw_response


class TestMain:
    @staticmethod
    def test_event_info_command(mocker):
        # mocking demisto environment
        mocker.patch.object(demisto, 'params', return_value={'hostname': 'https://localhost'})
        # mocker.patch.object(demisto, 'command', return_value='nw-events-info')
        mocker.patch.object(demisto, 'command', return_value='test-module')
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'doLogin')
        results = mocker.patch.object(demisto, 'results')

        # mocking command requests
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getTimeRange',
                            return_value=(datetime(1600, 11, 5).timestamp(), datetime(2020, 11, 5).timestamp()))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getMetaInformation',
                            return_value={})

        RsaNetWitnessPacketsAndLogsV2.main()
        assert len(results.call_args_list) == 1
        assert results.call_args_list[0].args[0] == 'ok'
        # assert len(results.call_args_list) == 3
        # assert {
        #     'Range':
        #     'Range of Session Ids', 'Start Range': 1,
        #     'End Range': 100} in results.call_args_list[0].args[0]['Contents']
        # assert results.call_args_list[1].args[0]['Contents'][2]['Range type'] == 'Meta Not Indexed'  # unindexed
        # assert results.call_args_list[1].args[0]['Contents'][2]['Count'] == 1  # unindexed

        # assert results.call_args_list[2].args[0]['Contents']['INDEX_NONE'] == ['NoIndex']
        # assert results.call_args_list[2].args[0]['Contents']['INDEX_KEY'] == ['KeyIndex']
        # assert results.call_args_list[2].args[0]['Contents']['INDEX_VALUE'] == ['ValueIndex']

        # # assert True
