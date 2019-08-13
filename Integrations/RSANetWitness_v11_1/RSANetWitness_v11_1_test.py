from datetime import datetime

import demistomock as demisto


def test_get_timestamp(mocker):
    def mock_demisto():
        mocked_dict = {
            'server': '',
            'credentials': {
                'identifier': '',
                'password': ''
            },
            'insecure': '',
            'version': '',
            'isFetch': ''
        }
        mocker.patch.object(demisto, 'params', return_value=mocked_dict)
        import RSANetWitness_v11_1
        mocker.patch.object(RSANetWitness_v11_1, 'get_token', return_value=None)

    mock_demisto()
    from RSANetWitness_v11_1 import get_timestamp
    stamps_to_check = {
        "2019-08-13T09:56:02.000000Z",
        "2019-08-13T09:56:02.440Z",
        "2019-08-13T09:56:02Z",
        "2019-08-13T09:56:02.000000",
        "2019-08-13T09:56:02.440",
        "2019-08-13T09:56:02"
    }
    expected = "2019-08-13 09:56:02"
    for timestamp in stamps_to_check:
        result = str(get_timestamp(timestamp))
        assert expected in result, "\n\tExpected: {}\n\tResult: {}\n\tInput timestamp: {}" \
                                   "".format(expected, result, timestamp)


def test_fetch_incidents(mocker):
    def mock_demisto():
        from RSANetWitness_v11_1 import get_timestamp
        mocker.patch.object(demisto, "getLastRun", return_value={
            "timestamp": get_timestamp("2019-08-13T09:56:02.000000")
        })
        mocker.patch.object(demisto, 'incidents')

    from RSANetWitness_v11_1 import fetch_incidents
    mock_demisto()