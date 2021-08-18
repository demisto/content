from datetime import datetime
import demistomock as demisto
import RsaNetWitnessPacketsAndLogsV2


class TestMain:
    @staticmethod
    def test_event_info_command(mocker, requests_mock):
        mocker.patch.object(demisto, 'params', return_value={'hostname': 'https://localhost'})
        mocker.patch.object(demisto, 'command', return_value='nw-events-info')
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'doLogin')
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getTimeRange',
                            return_value=(datetime(1600, 11, 5).timestamp(), datetime(2020, 11, 5).timestamp()))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getSessionIdRange',
                            return_value=(1, 100))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getMetaIdRange',
                            return_value=(101, 1000))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getTimeRange',
                            return_value=('1970-01-01T00:20:00Z', '2020-01-01T20:20:20Z'))
        mocker.patch.object(RsaNetWitnessPacketsAndLogsV2.NwCoreClient, 'getMetaInformation',
                            return_value={
                                'Meta1': RsaNetWitnessPacketsAndLogsV2.NwMeta(),
                            })
        # requests_mock.get('https://localhost')

        RsaNetWitnessPacketsAndLogsV2.main()
        # assert True
